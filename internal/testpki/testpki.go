// Package testpki builds throwaway certificate hierarchies for tests.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// Cert is a certificate plus its key.
type Cert struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

var serial int64 = 1000

// Opts tweaks generated certificates.
type Opts struct {
	NotBefore, NotAfter time.Time
	Key                 crypto.Signer // reuse a key (cross-signing)
	DNS                 []string
	IPs                 []net.IP
}

func gen(cn string, isCA bool, parent *Cert, o Opts) *Cert {
	key := o.Key
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		key = k
	}
	serial++
	nb, na := o.NotBefore, o.NotAfter
	if nb.IsZero() {
		nb = time.Now().Add(-24 * time.Hour)
	}
	if na.IsZero() {
		na = time.Now().Add(365 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Test PKI"}},
		NotBefore:             nb,
		NotAfter:              na,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              o.DNS,
		IPAddresses:           o.IPs,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	signer, parentCert := key, tmpl
	if parent != nil {
		signer, parentCert = parent.Key, parent.Cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), signer)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &Cert{Cert: c, Key: key}
}

// Root creates a self-signed CA.
func Root(cn string, o ...Opts) *Cert { return gen(cn, true, nil, first(o)) }

// Intermediate creates a CA signed by parent.
func Intermediate(cn string, parent *Cert, o ...Opts) *Cert { return gen(cn, true, parent, first(o)) }

// Leaf creates an end-entity certificate signed by parent.
func Leaf(cn string, parent *Cert, o ...Opts) *Cert {
	op := first(o)
	if op.DNS == nil && op.IPs == nil {
		op.DNS = []string{cn}
	}
	return gen(cn, false, parent, op)
}

func first(o []Opts) Opts {
	if len(o) > 0 {
		return o[0]
	}
	return Opts{}
}

// TLSCert builds a tls.Certificate presenting chain (leaf first).
func TLSCert(leaf *Cert, chain ...*Cert) tls.Certificate {
	tc := tls.Certificate{PrivateKey: leaf.Key, Leaf: leaf.Cert, Certificate: [][]byte{leaf.Cert.Raw}}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Cert.Raw)
	}
	return tc
}

// X509 extracts certificates.
func X509(cs ...*Cert) []*x509.Certificate {
	out := make([]*x509.Certificate, len(cs))
	for i, c := range cs {
		out[i] = c.Cert
	}
	return out
}
