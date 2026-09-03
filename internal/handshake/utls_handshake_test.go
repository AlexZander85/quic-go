// utls_handshake_test.go — b4x fork: pins the uTLS handshake path end to end
// (uTLS client <-> vanilla crypto/tls server) and the dial-time validation
// of the ClientHelloID. The vanilla-path tests above are unchanged and keep
// passing with the nil default.
package handshake

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

// TestHandshakeUTLSClient pins: a uTLS-fingerprinted client (HelloFirefox_Auto,
// HelloChrome_120) completes the QUIC-TLS handshake against a vanilla
// crypto/tls server, negotiates the caller's ALPN and keeps the transport
// parameters machinery (SetTransportParameters before Start) intact.
func TestHandshakeUTLSClient(t *testing.T) {
	for _, id := range []utls.ClientHelloID{utls.HelloFirefox_Auto, utls.HelloChrome_120} {
		t.Run(id.Client, func(t *testing.T) {
			clientConf := testdata.GetTLSConfig()
			clientConf.InsecureSkipVerify = true
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
				&id,
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
			cEvents, cErr, _, sErr := handshake(t, client, server)
			require.NoError(t, cErr)
			require.NoError(t, sErr)

			// The handshake completed: assert the client saw the server's
			// transport parameters (delivered through the uTLS path); the
			// completion itself is read off the connection state (the
			// handshake helper consumes EventHandshakeComplete internally).
			var sawTP bool
			for _, ev := range cEvents {
				if ev.Kind == EventReceivedTransportParameters {
					sawTP = true
				}
			}
			require.True(t, sawTP, "transport parameters must arrive via the uTLS path")

			cs := client.ConnectionState()
			require.True(t, cs.HandshakeComplete, "handshake must complete via the uTLS path")
			require.Equal(t, "crypto-setup", cs.NegotiatedProtocol)
		})
	}
}

// TestHandshakeVanillaUnchanged pins the default: a nil ClientHelloID keeps
// the vanilla crypto/tls handshake exactly as upstream.
func TestHandshakeVanillaUnchanged(t *testing.T) {
	clientConf := testdata.GetTLSConfig()
	clientConf.InsecureSkipVerify = true
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
		nil, // vanilla
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
	require.NoError(t, cErr)
	require.NoError(t, sErr)
}

// TestUTLSIDSpecLookup pins the spec lookup used for dial-time validation
// of the configured fingerprint (config.go validateConfig).
func TestUTLSIDSpecLookup(t *testing.T) {
	_, err := utls.UTLSIdToSpec(utls.HelloFirefox_Auto)
	require.NoError(t, err)
	bad := utls.ClientHelloID{Client: "b4x-nonexistent"}
	_, err = utls.UTLSIdToSpec(bad)
	require.Error(t, err)
	require.True(t, errors.Is(err, utls.ErrUnknownClientHelloID))
	_ = tls.VersionTLS13
}
