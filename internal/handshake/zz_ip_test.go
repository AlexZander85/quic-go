package handshake

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

func TestHandshakeUTLSIPServerName(t *testing.T) {
	clientConf := testdata.GetTLSConfig()
	clientConf.InsecureSkipVerify = true
	clientConf.ServerName = "127.0.0.1"
	clientConf.NextProtos = []string{"crypto-setup"}
	serverConf := testdata.GetTLSConfig()
	serverConf.NextProtos = []string{"crypto-setup"}

	client := NewCryptoSetupClient(
		protocol.ConnectionID{},
		&wire.TransportParameters{ActiveConnectionIDLimit: 2},
		clientConf,
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("client"),
		protocol.Version1,
		&[]utls.ClientHelloID{utls.HelloFirefox_Auto}[0],
	)
	var token protocol.StatelessResetToken
	serverTP := wire.TransportParameters{ActiveConnectionIDLimit: 2, StatelessResetToken: &token}
	server := NewCryptoSetupServer(
		protocol.ConnectionID{},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 1234},
		&net.UDPAddr{IP: net.IPv6loopback, Port: 4321},
		&serverTP,
		serverConf,
		false,
		utils.NewRTTStats(),
		nil,
		utils.DefaultLogger.WithPrefix("server"),
		protocol.Version1,
	)
	_, cErr, _, sErr := handshake(t, client, server)
	requireNoErr(t, cErr, sErr)
}

func requireNoErr(t *testing.T, errs ...error) {
	t.Helper()
	for _, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
}

var _ = tls.VersionTLS13
var _ = context.Background
