package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	dnsproxy "github.com/curdbecker/grpc-dnsproxy/pkg"

	"github.com/txn2/txeh"
)

func main() {
	cfg := dnsproxy.Config{}

	var hostsPath string
	var ttl uint

	flag.StringVar(&cfg.ListenInternal, "listen-internal", "", "Unix socket path to listen on for internal requests")
	flag.StringVar(&cfg.ListenExternal, "listen-external", "", "Unix socket path to listen on for external requests")
	flag.StringVar(&hostsPath, "hosts", "", "hosts file for lookups")
	flag.DurationVar(&cfg.UpstreamTimeout, "timeout", 4*time.Second, "upstream resolver timeout for external lookups")
	flag.UintVar(&ttl, "ttl", 60, "TTL (seconds) for hosts file answers")
	flag.BoolVar(&cfg.LogQueries, "log", false, "log every query and its outcome")
	flag.Parse()
	cfg.HostsTTL = uint32(ttl)

	if hostsPath != "" {
		var err error
		cfg.Hosts, err = txeh.NewHosts(&txeh.HostsConfig{
			ReadFilePath: hostsPath,
		})
		if err != nil {
			log.Fatalf("failed to read hosts file: %s", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := dnsproxy.Run(ctx, cfg); err != nil {
		log.Fatalf("dnsproxy: %v", err)
	}
	log.Println("dnsproxy: shut down")
}
