package quic_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/testdata"
)

// TestIntegrationUTLSClient against a vanilla quic-go server (quic.Listener).
func TestIntegrationUTLSClient(t *testing.T) {
	ln, err := quic.Listen(
		newUDPConnLocal(t),
		(&tls.Config{Certificates: testdata.GetTLSConfig().Certificates, NextProtos: []string{"h3"}}),
		&quic.Config{MaxIncomingStreams: 32},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		_ = c
	}()

	id := utls.HelloFirefox_Auto
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := quic.Dial(
		ctx,
		newUDPConnLocal(t),
		ln.Addr(),
		&tls.Config{ServerName: "127.0.0.1", InsecureSkipVerify: true, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
		&quic.Config{UTLSClientHelloID: &id, InitialPacketSize: 1250, KeepAlivePeriod: 30 * time.Second, MaxIncomingStreams: 64},
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.CloseWithError(0, "")
	t.Logf("handshake OK: proto=%q", c.ConnectionState().TLS.NegotiatedProtocol)
}

func newUDPConnLocal(t *testing.T) net.PacketConn {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	return uc
}
