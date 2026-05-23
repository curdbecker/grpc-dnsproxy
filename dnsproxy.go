// dnsproxy: CoreDNS gRPC DnsService implementation on a Unix socket.
//
// Protocol on the wire is exactly what the CoreDNS grpc plugin defines:
//
//	service coredns.dns.DnsService {
//	  rpc Query (DnsPacket) returns (DnsPacket);
//	}
//	message DnsPacket { bytes msg = 1; }
//
// `msg` carries a raw DNS wire-format packet (the same bytes you'd
// see on UDP/53), so the actual resolution is regular DNS — the gRPC
// is just framing.
//
// Lookup policy: host file first (if supplied), then forward unmatched
// queries to the host's resolvers in the given resolv.con
//
// Transport: gRPC (HTTP/2 prior-knowledge h2c) over a Unix socket.
// google.golang.org/grpc handles all HTTP/2 framing, trailers and
// status codes correctly; we just register the service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coredns/coredns/pb"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/docker/docker/libnetwork/resolvconf"
	"github.com/docker/docker/libnetwork/types"
	"github.com/miekg/dns"
	"github.com/txn2/txeh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	upstreamTO time.Duration
	defaultTTL uint32
	logQueries bool
)

func listen(listenPath string, hosts *txeh.Hosts, nameservers []string) func() {
	os.Remove(listenPath)

	l, err := net.Listen("unix", listenPath)
	if err != nil {
		log.Fatalf("listen %s: %v", listenPath, err)
	}
	if err := os.Chmod(listenPath, 0666); err != nil {
		log.Fatalf("chmod %s: %v", listenPath, err)
	}

	srv := grpc.NewServer()
	pb.RegisterDnsServiceServer(srv, &dnsService{
		hosts:       hosts,
		socket:      listenPath,
		nameservers: nameservers,
	})

	log.Printf("listening on unix:%s", listenPath)
	go func() {
		if err := srv.Serve(l); err != nil {
			log.Fatalf("serve: %v", err)
		}
	}()

	return func() {
		log.Printf("shutting down listener on %s", listenPath)
		srv.GracefulStop()
		os.Remove(listenPath)
	}
}

func main() {
	var resolvconfPath string
	var listenInternalPath string
	var listenExternalPath string
	var hostsPath string

	flag.StringVar(&listenInternalPath, "listen-internal", "", "Unix socket path to listen on for internal requests")
	flag.StringVar(&listenExternalPath, "listen-external", "", "Unix socket path to listen on for external requests")
	flag.StringVar(&hostsPath, "hosts", "", "hosts file for lookups")
	flag.StringVar(&resolvconfPath, "resolvconf", "/etc/resolv.conf", "path to resolv.conf - default /etc/resolv.conf")
	flag.DurationVar(&upstreamTO, "timeout", 4*time.Second, "upstream resolver timeout for external lookups")
	var ttl uint
	flag.UintVar(&ttl, "ttl", 60, "TTL (seconds) for hosts file answers")
	flag.BoolVar(&logQueries, "log", false, "log every query and its outcome")
	flag.Parse()
	defaultTTL = uint32(ttl)

	if listenInternalPath == "" && listenExternalPath == "" {
		log.Fatalf("must provide one of -listen-internal or listen-external")
	}

	var hosts *txeh.Hosts
	var err error
	if hostsPath != "" {
		hosts, err = txeh.NewHosts(&txeh.HostsConfig{
			ReadFilePath: hostsPath,
		})
		if err != nil {
			log.Fatalf("failed to read hosts file: %s", err)
		}
	}

	var resolvconfBytes []byte
	if resolvconfBytes, err = os.ReadFile(resolvconfPath); err != nil {
		log.Fatalf("failed to read %s: %s", resolvconfPath, err)
	}
	nameservers := resolvconf.GetNameservers(resolvconfBytes, types.IP)
	if len(nameservers) == 0 {
		log.Fatalf("no nameservers found in %s", resolvconfPath)
	}

	if listenInternalPath != "" {
		defer listen(listenInternalPath, hosts, nameservers)()
	}

	if listenExternalPath != "" {
		defer listen(listenExternalPath, hosts, nameservers)()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
}

// ---------- gRPC service ----------

type dnsService struct {
	pb.UnimplementedDnsServiceServer
	hosts       *txeh.Hosts
	socket      string
	nameservers []string
	nsIndex     int
}

func (s *dnsService) Query(ctx context.Context, in *pb.DnsPacket) (*pb.DnsPacket, error) {
	q := new(dns.Msg)
	if err := q.Unpack(in.Msg); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unpack DNS message: %v", err)
	}

	var reply *dns.Msg
	var source string

	if s.hosts != nil {
		reply = s.lookupInHosts(q)
		source = "hosts"
	}
	if reply == nil {
		source = s.getNextNameserver()
		reply = s.forwardToUpstream(ctx, q, source)
	}

	if logQueries {
		log.Printf("%s: result by %s -> response:\n%s", s.socket, source, reply)
	}

	out, err := reply.Pack()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "pack DNS message: %v", err)
	}
	return &pb.DnsPacket{Msg: out}, nil
}

func makeQueryResponse(q *dns.Msg, responseCode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Authoritative = true
	resp.RecursionAvailable = true
	resp.Rcode = responseCode

	return resp
}

func (s *dnsService) getNextNameserver() string {
	nameserver := s.nameservers[s.nsIndex]

	s.nsIndex += 1
	if s.nsIndex >= len(s.nameservers) {
		s.nsIndex = 0
	}

	return fmt.Sprintf("[%s]:%d", nameserver, 53)
}

func (s *dnsService) lookupInHosts(q *dns.Msg) *dns.Msg {
	if len(q.Question) > 1 {
		log.Print("multiple questions received for query - first question is answered")
	}

	qq := q.Question[0]
	hdr := dns.RR_Header{Name: dns.Fqdn(qq.Name), Class: dns.ClassINET,
		Ttl: defaultTTL, Rrtype: qq.Qtype}
	var records []dns.RR

	switch qq.Qtype {
	case dns.TypeA:
		found, answer, _ := s.hosts.HostAddressLookup(qq.Name, txeh.IPFamilyV4)
		if !found {
			break
		}
		v4 := net.ParseIP(answer).To4()
		records = append(records, &dns.A{Hdr: hdr, A: v4})

	case dns.TypeAAAA:
		found, answer, _ := s.hosts.HostAddressLookup(qq.Name, txeh.IPFamilyV6)
		if !found {
			break
		}
		v6 := net.ParseIP(answer)
		records = append(records, &dns.AAAA{Hdr: hdr, AAAA: v6})
	case dns.TypePTR:
		address := dnsutil.ExtractAddressFromReverse(qq.Name)
		for _, hostname := range s.hosts.ListHostsByIP(address) {
			records = append(records, &dns.PTR{Hdr: hdr, Ptr: hostname})
		}
	}

	if len(records) == 0 {
		return nil
	}

	response := makeQueryResponse(q, dns.RcodeSuccess)
	response.Answer = records

	return response
}

func (s *dnsService) forwardToUpstream(ctx context.Context,
	q *dns.Msg, nameserver string) *dns.Msg {

	client := new(dns.Client)
	ctx, cancel := context.WithTimeout(ctx, upstreamTO)
	defer cancel()

	forwarded, _, err := client.ExchangeContext(ctx, q, nameserver)
	if err != nil || forwarded == nil {
		log.Printf("forwarding query failed: %s -> %s", q, err)
		return makeQueryResponse(q, dns.RcodeServerFailure)
	}
	return forwarded
}
