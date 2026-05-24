// CoreDNS gRPC DnsService implementation on a Unix socket.
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
package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
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

type Config struct {
	// At least one of these must be set.
	ListenInternal string
	ListenExternal string

	// Optional. If empty, hosts-file lookups are skipped.
	Hosts *txeh.Hosts

	// Upstream nameservers
	Nameservers []string

	// Upstream resolver timeout. Defaults to 4s if zero.
	UpstreamTimeout time.Duration

	// TTL for hosts-file answers in seconds. Defaults to 60 if zero.
	HostsTTL uint32

	// Log every query and its outcome.
	LogQueries bool
}

func GetNameserversFromResolvConf(resolvconfPath string) ([]string, error) {
	var resolvconfBytes []byte
	var err error

	if resolvconfBytes, err = os.ReadFile(resolvconfPath); err != nil {
		return nil, fmt.Errorf("failed to read %s: %s", resolvconfPath, err)
	}

	nameservers := resolvconf.GetNameservers(resolvconfBytes, types.IP)
	if len(nameservers) == 0 {
		return nil, fmt.Errorf("no nameservers found in %s", resolvconfPath)
	}

	return nameservers, nil
}

// Run starts the resolver(s) and blocks until ctx is cancelled. All
// gRPC servers are GracefulStop()ed and socket files are removed
// before Run returns.
func Run(ctx context.Context, cfg Config) error {
	var err error

	if cfg.ListenInternal == "" && cfg.ListenExternal == "" {
		return errors.New("dnsproxy: at least one of ListenInternal/ListenExternal is required")
	}

	if len(cfg.Nameservers) == 0 {
		resolvconfPath := "/etc/resolv.conf"
		cfg.Nameservers, err = GetNameserversFromResolvConf(resolvconfPath)
		if err != nil {
			return fmt.Errorf("failed to open %s: %s", resolvconfPath, err)
		}
	}

	if cfg.UpstreamTimeout == 0 {
		cfg.UpstreamTimeout = 4 * time.Second
	}
	if cfg.HostsTTL == 0 {
		cfg.HostsTTL = 60
	}

	if cfg.ListenInternal != "" {
		defer startListener(cfg.ListenInternal, cfg)()
	}

	if cfg.ListenExternal != "" {
		defer startListener(cfg.ListenExternal, cfg)()
	}

	<-ctx.Done()
	return nil
}

func startListener(listenPath string, config Config) func() {
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
		socket: listenPath,
		config: config,
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

// ---------- gRPC service ----------

type dnsService struct {
	pb.UnimplementedDnsServiceServer
	config  Config
	socket  string
	nsIndex int
}

func (s *dnsService) Query(ctx context.Context, in *pb.DnsPacket) (*pb.DnsPacket, error) {
	q := new(dns.Msg)
	if err := q.Unpack(in.Msg); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unpack DNS message: %v", err)
	}

	var reply *dns.Msg
	var source string

	if s.config.Hosts != nil {
		reply = s.lookupInHosts(q)
		source = "hosts"
	}
	if reply == nil {
		source = s.getNextNameserver()
		reply = s.forwardToUpstream(ctx, q, source)
	}

	if s.config.LogQueries {
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
	nameserver := s.config.Nameservers[s.nsIndex]

	s.nsIndex += 1
	if s.nsIndex >= len(s.config.Nameservers) {
		s.nsIndex = 0
	}

	return fmt.Sprintf("[%s]:%d", nameserver, 53)
}

func (s *dnsService) lookupInHosts(q *dns.Msg) *dns.Msg {
	if len(q.Question) > 1 {
		log.Print("multiple questions received for query - first question is answered")
	}
	hosts := s.config.Hosts

	qq := q.Question[0]
	hdr := dns.RR_Header{Name: dns.Fqdn(qq.Name), Class: dns.ClassINET,
		Ttl: s.config.HostsTTL, Rrtype: qq.Qtype}
	var records []dns.RR

	switch qq.Qtype {
	case dns.TypeA:
		found, answer, _ := hosts.HostAddressLookup(qq.Name, txeh.IPFamilyV4)
		if !found {
			break
		}
		v4 := net.ParseIP(answer).To4()
		records = append(records, &dns.A{Hdr: hdr, A: v4})

	case dns.TypeAAAA:
		found, answer, _ := hosts.HostAddressLookup(qq.Name, txeh.IPFamilyV6)
		if !found {
			break
		}
		v6 := net.ParseIP(answer)
		records = append(records, &dns.AAAA{Hdr: hdr, AAAA: v6})
	case dns.TypePTR:
		address := dnsutil.ExtractAddressFromReverse(qq.Name)
		for _, hostname := range hosts.ListHostsByIP(address) {
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
	ctx, cancel := context.WithTimeout(ctx, s.config.UpstreamTimeout)
	defer cancel()

	forwarded, _, err := client.ExchangeContext(ctx, q, nameserver)
	if err != nil || forwarded == nil {
		log.Printf("forwarding query failed: %s -> %s", q, err)
		return makeQueryResponse(q, dns.RcodeServerFailure)
	}
	return forwarded
}
