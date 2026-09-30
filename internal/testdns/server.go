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
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp4", listener.Addr().String())
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
