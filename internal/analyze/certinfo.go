package analyze

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math"
	"strings"
	"time"

	"ca-chain-check/internal/config"
	"ca-chain-check/internal/truststore"
)

// Validity statuses.
const (
	StatusValid        = "valid"
	StatusExpired      = "expired"
	StatusNotYetValid  = "not_yet_valid"
	StatusExpiringSoon = "expiring_soon"
)

// CertInfo is the JSON view of one certificate.
type CertInfo struct {
	ID        string `json:"id"`     // node id used by paths and the diagram
	Index     int    `json:"index"`  // position as sent by server; -1 if not sent
	Source    string `json:"source"` // "presented" | "mozilla_store"
	SHA256    string `json:"sha256"`
	SHA1      string `json:"sha1"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	SubjectCN string `json:"subjectCN"`
	IssuerCN  string `json:"issuerCN"`
	Serial    string `json:"serial"`
	Version   int    `json:"version"`

	NotBefore     time.Time `json:"notBefore"`
	NotAfter      time.Time `json:"notAfter"`
	Status        string    `json:"status"`
	DaysRemaining int       `json:"daysRemaining"`

	KeyAlgorithm       string `json:"keyAlgorithm"`
	KeySize            int    `json:"keySize,omitempty"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`

	DNSNames    []string `json:"dnsNames,omitempty"`
	IPAddresses []string `json:"ipAddresses,omitempty"`
	Emails      []string `json:"emails,omitempty"`
	URIs        []string `json:"uris,omitempty"`

	SubjectKeyID   string   `json:"subjectKeyId,omitempty"`
	AuthorityKeyID string   `json:"authorityKeyId,omitempty"`
	IsCA           bool     `json:"isCA"`
	MaxPathLen     *int     `json:"maxPathLen,omitempty"`
	KeyUsage       []string `json:"keyUsage,omitempty"`
	ExtKeyUsage    []string `json:"extKeyUsage,omitempty"`
	Policies       []string `json:"policies,omitempty"`
	OCSPServers    []string `json:"ocspServers,omitempty"`
	IssuingURLs    []string `json:"issuingUrls,omitempty"`
	CRLs           []string `json:"crlDistributionPoints,omitempty"`

	SelfSigned      bool                    `json:"selfSigned"`
	InMozilla       bool                    `json:"inMozilla"`
	PendingDistrust *config.PendingDistrust `json:"pendingDistrust,omitempty"`

	// Set by chain analysis.
	OnTrustedPath bool   `json:"onTrustedPath"`
	Extraneous    string `json:"extraneous,omitempty"` // "", "unrelated", "alternate_path", "duplicate"
	DuplicateOf   int    `json:"duplicateOf,omitempty"`

	PEM string `json:"pem"`
}

var keyUsageNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Content Commitment"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Certificate Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:             "Any",
	x509.ExtKeyUsageServerAuth:      "TLS Web Server Authentication",
	x509.ExtKeyUsageClientAuth:      "TLS Web Client Authentication",
	x509.ExtKeyUsageCodeSigning:     "Code Signing",
	x509.ExtKeyUsageEmailProtection: "E-mail Protection",
	x509.ExtKeyUsageTimeStamping:    "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:     "OCSP Signing",
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

func cnOrDN(cn, dn string) string {
	if cn != "" {
		return cn
	}
	return dn
}

// isSelfSigned is true when subject == issuer and the cert verifies itself.
func isSelfSigned(c *x509.Certificate) bool {
	if string(c.RawSubject) != string(c.RawIssuer) {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func validity(c *x509.Certificate, now time.Time, soon time.Duration) (string, int) {
	days := int(math.Floor(c.NotAfter.Sub(now).Hours() / 24))
	switch {
	case now.Before(c.NotBefore):
		return StatusNotYetValid, days
	case now.After(c.NotAfter):
		return StatusExpired, days
	case c.NotAfter.Sub(now) < soon:
		return StatusExpiringSoon, days
	}
	return StatusValid, days
}

func describe(c *x509.Certificate, id string, index int, source string, o Options) CertInfo {
	sha1sum := sha1.Sum(c.Raw)
	fp := truststore.FingerprintSHA256(c)
	ci := CertInfo{
		ID: id, Index: index, Source: source,
		SHA256: fp, SHA1: hex.EncodeToString(sha1sum[:]),
		Subject: c.Subject.String(), Issuer: c.Issuer.String(),
		Serial:    colonHex(c.SerialNumber.Bytes()),
		Version:   c.Version,
		NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		DNSNames:           c.DNSNames, Emails: c.EmailAddresses,
		IsCA:        c.BasicConstraintsValid && c.IsCA,
		OCSPServers: c.OCSPServer, IssuingURLs: c.IssuingCertificateURL,
		CRLs:       c.CRLDistributionPoints,
		SelfSigned: isSelfSigned(c),
		PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
	}
	ci.SubjectCN = cnOrDN(c.Subject.CommonName, ci.Subject)
	ci.IssuerCN = cnOrDN(c.Issuer.CommonName, ci.Issuer)
	ci.Status, ci.DaysRemaining = validity(c, o.Now, o.ExpiringSoon)
	for _, ip := range c.IPAddresses {
		ci.IPAddresses = append(ci.IPAddresses, ip.String())
	}
	for _, u := range c.URIs {
		ci.URIs = append(ci.URIs, u.String())
	}
	if len(c.SubjectKeyId) > 0 {
		ci.SubjectKeyID = colonHex(c.SubjectKeyId)
	}
	if len(c.AuthorityKeyId) > 0 {
		ci.AuthorityKeyID = colonHex(c.AuthorityKeyId)
	}
	if ci.IsCA && (c.MaxPathLen > 0 || c.MaxPathLenZero) {
		v := c.MaxPathLen
		ci.MaxPathLen = &v
	}
	for _, k := range keyUsageNames {
		if c.KeyUsage&k.bit != 0 {
			ci.KeyUsage = append(ci.KeyUsage, k.name)
		}
	}
	for _, e := range c.ExtKeyUsage {
		if n, ok := extKeyUsageNames[e]; ok {
			ci.ExtKeyUsage = append(ci.ExtKeyUsage, n)
		} else {
			ci.ExtKeyUsage = append(ci.ExtKeyUsage, fmt.Sprintf("EKU(%d)", e))
		}
	}
	for _, oid := range c.UnknownExtKeyUsage {
		ci.ExtKeyUsage = append(ci.ExtKeyUsage, oid.String())
	}
	for _, p := range c.PolicyIdentifiers {
		ci.Policies = append(ci.Policies, p.String())
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		ci.KeyAlgorithm, ci.KeySize = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		ci.KeyAlgorithm, ci.KeySize = "ECDSA "+k.Curve.Params().Name, k.Curve.Params().BitSize
	case ed25519.PublicKey:
		ci.KeyAlgorithm, ci.KeySize = "Ed25519", 256
	default:
		ci.KeyAlgorithm = c.PublicKeyAlgorithm.String()
	}
	if o.Store != nil {
		ci.InMozilla = o.Store.Contains(fp)
	}
	if pd, ok := o.Pending[fp]; ok {
		pd := pd
		ci.PendingDistrust = &pd
	}
	return ci
}
