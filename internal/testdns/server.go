// Package testdns supplies local, deterministic DNS fixtures for tests.
package testdns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Start serves UDP and TCP on one loopback port. The test controls responses.
func Start(t testing.TB, handler dns.HandlerFunc) string {
	t.Helper()
	return start(t, "tcp4", "udp4", "127.0.0.1:0", handler)
}

// StartIPv6 skips the caller only when IPv6 loopback is unavailable.
func StartIPv6(t testing.TB, handler dns.HandlerFunc) string {
	t.Helper()
	return start(t, "tcp6", "udp6", "[::1]:0", handler)
}

func start(t testing.TB, tcp, udp, address string, handler dns.HandlerFunc) string {
	t.Helper()
	listener, err := net.Listen(tcp, address)
	if err != nil {
		if tcp == "tcp6" {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		t.Fatal(err)
	}
	packet, err := net.ListenPacket(udp, listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	for _, server := range []*dns.Server{
		{Listener: listener, Handler: handler},
		{PacketConn: packet, Handler: handler},
	} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() {
			if err := server.ActivateAndServe(); err != nil {
				t.Errorf("DNS fixture: %v", err)
			}
		}()
		<-ready
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := server.ShutdownContext(ctx); err != nil {
				t.Errorf("DNS fixture shutdown: %v", err)
			}
		})
	}
	return listener.Addr().String()
}

func Reply(rcode int, records ...string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Rcode = rcode
		m.RecursionAvailable = true
		for _, record := range records {
			rr, err := dns.NewRR(record)
			if err != nil {
				panic(err) // A broken fixture must fail the test.
			}
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	}
}
