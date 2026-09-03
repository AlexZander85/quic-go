// utls_conn.go — the uTLS seam of the b4x fork (github.com/AlexZander85/quic-go,
// branch b4x-utls, based on upstream v0.61.0).
//
// WHY THIS EXISTS: quic-go builds its ClientHello through crypto/tls
// (tls.QUICClient), whose byte layout (extension order, GREASE, key share
// selection) is a JA3/JA4 fingerprint no browser produces. uTLS produces
// byte-accurate browser hellos (HelloFirefox_Auto, HelloChrome_120, ...)
// and ships a QUIC event API mirroring crypto/tls's (UQUICConn /
// QUICEvent / QUICEncryptionLevel) — but the types are distinct, so
// cryptoSetup cannot consume it directly. This file adapts the uTLS QUIC
// connection to the internal quicConn interface; the vanilla path is
// byte-for-byte untouched and remains the default when
// quic.Config.UTLSClientHelloID is nil.
//
// Trust model (red line): uTLS changes the OBSERVED BYTES, never the
// verification. The converted utls.Config keeps the RootCAs /
// InsecureSkipVerify / VerifyPeerCertificate / VerifyConnection semantics
// of the caller's tls.Config.
//
// Mechanics (utls v1.8.2):
//   - the hello is built from the ClientHelloSpec, so the spec is
//     normalized for QUIC (RFC 9001): TLS 1.3 only in TLSVersMin/Max and
//     supported_versions — a browser preset drags its TCP-era 1.2 floor
//     along, which both trips UQUICConn's >= 1.3 gate and the server's
//     version check;
//   - the preset's own ALPN (h2/http-1.1 for a TCP browser) is overridden
//     with the caller's offer (h3) — real browsers offer h3 over QUIC;
//   - the QUIC transport parameters arrive via SetTransportParameters
//     (quic-go calls it before Start) and ride the hello as a raw
//     quic_transport_parameters (57) extension carrying exactly the bytes
//     quic-go marshaled;
//   - session resumption is disabled (no cache, session events off): one
//     full handshake per connection, no 0-RTT;
//   - a spec failure degrades permanently to the vanilla crypto/tls
//     connection (connectivity first; the error is logged).
package handshake

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"

	"github.com/quic-go/quic-go/internal/utils"
)

// quicConn is the minimal QUIC-TLS surface cryptoSetup consumes. It is
// satisfied natively by *tls.QUICConn (vanilla) and by *utlsQUICConn
// (fingerprinted) below.
type quicConnIface interface {
	Start(ctx context.Context) error
	Close() error
	HandleData(tls.QUICEncryptionLevel, []byte) error
	NextEvent() tls.QUICEvent
	ConnectionState() tls.ConnectionState
	SetTransportParameters([]byte)
	SendSessionTicket(tls.QUICSessionTicketOptions) error
	StoreSession(*tls.SessionState) error
}

var _ quicConnIface = (*tls.QUICConn)(nil)

// newUTLSClientConn builds the fingerprinted QUIC-TLS connection for the
// given ClientHelloID.
func newUTLSClientConn(tlsConf *tls.Config, id utls.ClientHelloID, logger utils.Logger) (quicConnIface, error) {
	ucfg := convertUTLSConfig(tlsConf)

	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, fmt.Errorf("utls: ClientHello spec %q: %w", id.Str(), err)
	}
	if err := overrideSpecALPN(&spec, tlsConf.NextProtos); err != nil {
		return nil, fmt.Errorf("utls: ALPN override: %w", err)
	}
	spec.TLSVersMin = utls.VersionTLS13
	spec.TLSVersMax = utls.VersionTLS13
	for _, ext := range spec.Extensions {
		if sv, ok := ext.(*utls.SupportedVersionsExtension); ok {
			sv.Versions = []uint16{utls.VersionTLS13}
		}
	}

	// RFC 6066: literal IP addresses are never sent in SNI — the vanilla
	// crypto/tls client omits the extension for them, and a preset hello
	// would otherwise carry an IP-literal SNI (the wire difference made
	// strict servers drop the ClientHello silently).
	if net.ParseIP(ucfg.ServerName) != nil {
		ucfg.ServerName = ""
		filtered := make([]utls.TLSExtension, 0, len(spec.Extensions))
		for _, ext := range spec.Extensions {
			if _, ok := ext.(*utls.SNIExtension); ok {
				continue
			}
			filtered = append(filtered, ext)
		}
		spec.Extensions = filtered
	}

	uq := utls.UQUICClient(&utls.QUICConfig{TLSConfig: ucfg}, utls.HelloCustom)
	return &utlsQUICConn{
		conn:    uq,
		spec:    &spec,
		tlsConf: tlsConf,
		logf:    logger.Errorf,
	}, nil
}

// convertUTLSConfig maps the caller's tls.Config onto the uTLS config with
// identical trust semantics. Client callbacks of identical signatures are
// carried over directly; VerifyConnection needs a ConnectionState adapter.
func convertUTLSConfig(c *tls.Config) *utls.Config {
	uc := &utls.Config{
		ServerName:                  c.ServerName,
		NextProtos:                  append([]string(nil), c.NextProtos...),
		MinVersion:                  tls.VersionTLS13, // UQUICConn requires >= TLS 1.3
		RootCAs:                     c.RootCAs,
		InsecureSkipVerify:          c.InsecureSkipVerify,
		CipherSuites:                c.CipherSuites,
		KeyLogWriter:                c.KeyLogWriter,
		Time:                        c.Time,
		Rand:                        c.Rand,
		SessionTicketsDisabled:      true, // one full handshake per connection; no 0-RTT
		DynamicRecordSizingDisabled: true,
	}
	for _, curve := range c.CurvePreferences {
		uc.CurvePreferences = append(uc.CurvePreferences, utls.CurveID(curve))
	}
	if len(c.Certificates) > 0 {
		uc.Certificates = make([]utls.Certificate, len(c.Certificates))
		for i, cert := range c.Certificates {
			uc.Certificates[i] = utls.Certificate{
				Certificate:                 cert.Certificate,
				PrivateKey:                  cert.PrivateKey,
				OCSPStaple:                  cert.OCSPStaple,
				SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
				Leaf:                        cert.Leaf,
			}
		}
	}
	if c.VerifyPeerCertificate != nil {
		// identical signature in uTLS
		uc.VerifyPeerCertificate = c.VerifyPeerCertificate
	}
	if c.VerifyConnection != nil {
		vc := c.VerifyConnection
		uc.VerifyConnection = func(cs utls.ConnectionState) error {
			return vc(connStateToTLS(cs))
		}
	}
	return uc
}

// overrideSpecALPN swaps the preset's ALPN extension for the caller's
// offer (the h3 carrier dialect), appending one when the preset has none.
func overrideSpecALPN(spec *utls.ClientHelloSpec, nextProtos []string) error {
	if len(nextProtos) == 0 {
		return nil
	}
	for i, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = append([]string(nil), nextProtos...)
			spec.Extensions[i] = alpn
			return nil
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{
		AlpnProtocols: append([]string(nil), nextProtos...),
	})
	return nil
}

// quicTransportParametersExtCode is the quic_transport_parameters
// extension code (0x39) used to carry the transport parameters in the
// ClientHello (GenericExtension — raw bytes from quic-go's marshaler).
const quicTransportParametersExtCode = 57

// utlsQUICConn adapts *utls.UQUICConn to the quicConn interface. The spec
// is applied lazily at SetTransportParameters — quic-go always hands the
// marshaled transport parameters over before Start, and the hello must
// carry them as a raw extension.
type utlsQUICConn struct {
	conn    *utls.UQUICConn
	spec    *utls.ClientHelloSpec
	tlsConf *tls.Config
	logf    func(format string, args ...any)

	params  []byte
	applied bool
	failure error
	focus   quicConnIface // set after a failure: the vanilla fallback
}

var _ quicConnIface = (*utlsQUICConn)(nil)

// failed reports whether the adapter must route to the vanilla fallback.
func (c *utlsQUICConn) failed() bool { return c.failure != nil }

// applySpecIfNeeded materializes the fingerprinted hello once (the transport
// parameters must already be known). A failure permanently switches the
// adapter to the vanilla fallback.
func (c *utlsQUICConn) applySpecIfNeeded() {
	if c.applied {
		return
	}
	c.applied = true
	if err := c.conn.ApplyPreset(c.spec); err != nil {
		c.logf("utls: apply preset failed, falling back to crypto/tls: %v", err)
		c.failure = err
		fallback := tls.QUICClient(&tls.QUICConfig{
			TLSConfig:           c.tlsConf,
			EnableSessionEvents: true,
		})
		fallback.SetTransportParameters(c.params)
		c.focus = fallback
	}
}

func (c *utlsQUICConn) Start(ctx context.Context) error {
	c.applySpecIfNeeded()
	if c.failed() {
		return c.focus.Start(ctx)
	}
	return c.conn.Start(ctx)
}

func (c *utlsQUICConn) Close() error {
	c.applySpecIfNeeded()
	if c.failed() {
		return c.focus.Close()
	}
	return c.conn.Close()
}

func (c *utlsQUICConn) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	c.applySpecIfNeeded()
	if c.failed() {
		return c.focus.HandleData(level, data)
	}
	return c.conn.HandleData(quicEncLevelFromTLS(level), data)
}

func (c *utlsQUICConn) NextEvent() tls.QUICEvent {
	c.applySpecIfNeeded()
	if c.failed() {
		return c.focus.NextEvent()
	}
	return quicEventFromUTLS(c.conn.NextEvent())
}

func (c *utlsQUICConn) ConnectionState() tls.ConnectionState {
	c.applySpecIfNeeded()
	if c.failed() {
		return c.focus.ConnectionState()
	}
	return connStateToTLS(c.conn.ConnectionState())
}

func (c *utlsQUICConn) SendSessionTicket(opts tls.QUICSessionTicketOptions) error {
	c.applySpecIfNeeded()
	if c.failed() {
		return c.focus.SendSessionTicket(opts)
	}
	return c.conn.SendSessionTicket(utls.QUICSessionTicketOptions{
		EarlyData: opts.EarlyData,
		Extra:     opts.Extra,
	})
}

func (c *utlsQUICConn) StoreSession(ss *tls.SessionState) error {
	c.applySpecIfNeeded()
	// Session events are disabled on the uTLS path (no resumption); the
	// fallback implements the vanilla behavior.
	return c.focus.StoreSession(ss)
}

func (c *utlsQUICConn) SetTransportParameters(params []byte) {
	c.params = append([]byte(nil), params...)
	if c.failure == nil {
		// The transport parameters ride the hello as a raw extension
		// carrying exactly the bytes quic-go marshaled. This is the last
		// moment before the hello is materialized.
		c.spec.Extensions = append(c.spec.Extensions, &utls.GenericExtension{
			Id:   quicTransportParametersExtCode,
			Data: c.params,
		})
	}
	c.applySpecIfNeeded()
	if c.failed() {
		c.focus.SetTransportParameters(params)
		return
	}
	c.conn.SetTransportParameters(params)
}

// ---- type conversions ---------------------------------------------------------

func quicEncLevelFromTLS(l tls.QUICEncryptionLevel) utls.QUICEncryptionLevel {
	switch l {
	case tls.QUICEncryptionLevelInitial:
		return utls.QUICEncryptionLevelInitial
	case tls.QUICEncryptionLevelEarly:
		return utls.QUICEncryptionLevelEarly
	case tls.QUICEncryptionLevelHandshake:
		return utls.QUICEncryptionLevelHandshake
	case tls.QUICEncryptionLevelApplication:
		return utls.QUICEncryptionLevelApplication
	default:
		return utls.QUICEncryptionLevelApplication
	}
}

func quicEventFromUTLS(ev utls.QUICEvent) tls.QUICEvent {
	out := tls.QUICEvent{
		Data:  ev.Data,
		Suite: ev.Suite,
	}
	switch ev.Kind {
	case utls.QUICNoEvent:
		out.Kind = tls.QUICNoEvent
	case utls.QUICSetReadSecret:
		out.Kind = tls.QUICSetReadSecret
		out.Level = encLevelFromUTLS(ev.Level)
	case utls.QUICSetWriteSecret:
		out.Kind = tls.QUICSetWriteSecret
		out.Level = encLevelFromUTLS(ev.Level)
	case utls.QUICWriteData:
		out.Kind = tls.QUICWriteData
		out.Level = encLevelFromUTLS(ev.Level) // utls sets Level on WriteData too
	case utls.QUICTransportParameters:
		out.Kind = tls.QUICTransportParameters
	case utls.QUICTransportParametersRequired:
		out.Kind = tls.QUICTransportParametersRequired
	case utls.QUICRejectedEarlyData:
		out.Kind = tls.QUICRejectedEarlyData
	case utls.QUICHandshakeDone:
		out.Kind = tls.QUICHandshakeDone
	case utls.QUICResumeSession, utls.QUICStoreSession:
		// Session events are disabled on the uTLS path; unreachable.
		return tls.QUICEvent{Kind: tls.QUICNoEvent}
	default:
		return tls.QUICEvent{Kind: tls.QUICNoEvent}
	}
	return out
}

func encLevelFromUTLS(l utls.QUICEncryptionLevel) tls.QUICEncryptionLevel {
	switch l {
	case utls.QUICEncryptionLevelInitial:
		return tls.QUICEncryptionLevelInitial
	case utls.QUICEncryptionLevelEarly:
		return tls.QUICEncryptionLevelEarly
	case utls.QUICEncryptionLevelHandshake:
		return tls.QUICEncryptionLevelHandshake
	case utls.QUICEncryptionLevelApplication:
		return tls.QUICEncryptionLevelApplication
	default:
		return tls.QUICEncryptionLevelApplication
	}
}

func connStateToTLS(cs utls.ConnectionState) tls.ConnectionState {
	return tls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		DidResume:                   cs.DidResume,
		CipherSuite:                 cs.CipherSuite,
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
		ServerName:                  cs.ServerName,
	}
}
