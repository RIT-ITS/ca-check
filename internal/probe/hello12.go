package probe

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/cryptobyte"
)

// chain12 is what a TLS 1.2 server sends in the clear before key exchange.
type chain12 struct {
	certs  []*x509.Certificate
	suite  uint16
	staple []byte
}

// fetchChain12 sends a plain TLS 1.2 ClientHello offering only the given
// cipher suites and reads the server's Certificate (and CertificateStatus)
// messages, which TLS 1.2 sends unencrypted. It does not finish the
// handshake. This is used to ask for a server's other (RSA or ECDSA)
// certificate: Go's own client sends extensions some servers, Google's
// among them, answer with a handshake failure when RSA-only suites are
// offered.
func fetchChain12(conn net.Conn, sni string, suites []uint16) (*chain12, error) {
	hello, err := clientHello12(sni, suites)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(hello); err != nil {
		return nil, err
	}
	hs := &handshakeReader{r: conn}
	out := &chain12{}
	for {
		typ, body, err := hs.next()
		if err != nil {
			return nil, err
		}
		switch typ {
		case 2: // ServerHello
			s := cryptobyte.String(body)
			var vers uint16
			var random, session []byte
			if !s.ReadUint16(&vers) || !s.ReadBytes(&random, 32) || !s.ReadUint8LengthPrefixed((*cryptobyte.String)(&session)) || !s.ReadUint16(&out.suite) {
				return nil, errors.New("malformed ServerHello")
			}
			if vers != tls.VersionTLS12 {
				return nil, fmt.Errorf("server chose %s, not TLS 1.2", tls.VersionName(vers))
			}
		case 11: // Certificate
			s := cryptobyte.String(body)
			var list cryptobyte.String
			if !s.ReadUint24LengthPrefixed(&list) {
				return nil, errors.New("malformed Certificate message")
			}
			for !list.Empty() {
				var der []byte
				if !list.ReadUint24LengthPrefixed((*cryptobyte.String)(&der)) {
					return nil, errors.New("malformed Certificate message")
				}
				c, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, fmt.Errorf("server certificate: %w", err)
				}
				out.certs = append(out.certs, c)
			}
		case 22: // CertificateStatus
			s := cryptobyte.String(body)
			var statusType uint8
			var resp []byte
			if s.ReadUint8(&statusType) && statusType == 1 && s.ReadUint24LengthPrefixed((*cryptobyte.String)(&resp)) {
				out.staple = resp
			}
		case 12, 13, 14: // ServerKeyExchange, CertificateRequest, ServerHelloDone
			if len(out.certs) == 0 {
				return nil, errors.New("server sent no certificates")
			}
			return out, nil
		}
	}
}

// clientHello12 builds a TLS 1.2 ClientHello record similar to OpenSSL's.
func clientHello12(sni string, suites []uint16) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint8(22) // handshake record
	b.AddUint16(tls.VersionTLS10)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1) // ClientHello
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(tls.VersionTLS12)
			b.AddBytes(random)
			b.AddUint8(0) // no session ID
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, s := range suites {
					b.AddUint16(s)
				}
				b.AddUint16(0x00ff) // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
			})
			b.AddUint8(1)
			b.AddUint8(0) // no compression
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				if sni != "" {
					ext(b, 0, func(b *cryptobyte.Builder) {
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddUint8(0) // host_name
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(sni)) })
						})
					})
				}
				ext(b, 11, func(b *cryptobyte.Builder) { // ec_point_formats: uncompressed
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
				})
				ext(b, 10, func(b *cryptobyte.Builder) { // supported_groups
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, g := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521} {
							b.AddUint16(uint16(g))
						}
					})
				})
				ext(b, 13, func(b *cryptobyte.Builder) { // signature_algorithms
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, s := range []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512,
							tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512,
							tls.PKCS1WithSHA256, tls.PKCS1WithSHA384, tls.PKCS1WithSHA512,
							tls.ECDSAWithSHA1, tls.PKCS1WithSHA1,
						} {
							b.AddUint16(uint16(s))
						}
					})
				})
				ext(b, 5, func(b *cryptobyte.Builder) { // status_request: OCSP, no responder IDs or extensions
					b.AddUint8(1)
					b.AddUint16(0)
					b.AddUint16(0)
				})
				ext(b, 23, func(*cryptobyte.Builder) {}) // extended_master_secret
			})
		})
	})
	return b.Bytes()
}

func ext(b *cryptobyte.Builder, id uint16, body func(*cryptobyte.Builder)) {
	b.AddUint16(id)
	b.AddUint16LengthPrefixed(body)
}

// handshakeReader splits TLS records into handshake messages.
type handshakeReader struct {
	r   io.Reader
	buf []byte
}

// alertNames match the wording of Go's crypto/tls errors.
var alertNames = map[uint8]string{
	40: "handshake failure", 47: "illegal parameter", 50: "decode error",
	70: "protocol version", 71: "insufficient security", 80: "internal error", 112: "unrecognized name",
}

func (h *handshakeReader) next() (uint8, []byte, error) {
	for {
		if len(h.buf) >= 4 {
			n := int(h.buf[1])<<16 | int(h.buf[2])<<8 | int(h.buf[3])
			if len(h.buf) >= 4+n {
				typ, body := h.buf[0], h.buf[4:4+n]
				h.buf = h.buf[4+n:]
				return typ, body, nil
			}
		}
		var hdr [5]byte
		if _, err := io.ReadFull(h.r, hdr[:]); err != nil {
			return 0, nil, err
		}
		n := int(binary.BigEndian.Uint16(hdr[3:]))
		if n > 1<<14+2048 {
			return 0, nil, errors.New("TLS record too large")
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(h.r, body); err != nil {
			return 0, nil, err
		}
		switch hdr[0] {
		case 21: // alert
			if len(body) == 2 {
				if name, ok := alertNames[body[1]]; ok {
					return 0, nil, fmt.Errorf("remote error: tls: %s", name)
				}
				return 0, nil, fmt.Errorf("remote error: tls: alert %d", body[1])
			}
			return 0, nil, errors.New("malformed alert")
		case 22:
			h.buf = append(h.buf, body...)
			if len(h.buf) > 1<<20 {
				return 0, nil, errors.New("handshake too large")
			}
		default:
			return 0, nil, fmt.Errorf("unexpected TLS record type %d", hdr[0])
		}
	}
}
