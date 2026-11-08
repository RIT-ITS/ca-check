package analyze

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Staple describes the OCSP response the server stapled to the handshake.
type Staple struct {
	Present    bool       `json:"present"`
	MustStaple bool       `json:"mustStaple"`       // leaf has the TLS Feature status_request extension
	Status     string     `json:"status,omitempty"` // good | revoked | unknown | error
	ThisUpdate *time.Time `json:"thisUpdate,omitempty"`
	NextUpdate *time.Time `json:"nextUpdate,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	Error      string     `json:"error,omitempty"`
}

var oidTLSFeature = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

// mustStaple reports whether the certificate's TLS Feature extension
// (RFC 7633) lists status_request (5).
func mustStaple(c *x509.Certificate) bool {
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidTLSFeature) {
			continue
		}
		var features []int
		if _, err := asn1.Unmarshal(e.Value, &features); err != nil {
			return false
		}
		for _, f := range features {
			if f == 5 {
				return true
			}
		}
	}
	return false
}

// staple checks the stapled response against the leaf and its issuer on the
// best path.
func (a *analyzer) staple() *Staple {
	leaf := a.nodes[a.order[0]].cert
	s := &Staple{Present: len(a.o.Staple) > 0, MustStaple: mustStaple(leaf)}
	if !s.Present {
		return s
	}
	var issuer *x509.Certificate
	if best := a.bestPath(); best != nil && len(best.Nodes) > 1 {
		for fp, id := range a.ids {
			if id == best.Nodes[1] {
				issuer = a.nodes[fp].cert
			}
		}
	}
	if issuer == nil {
		s.Status, s.Error = RevError, "the leaf's issuer is not known, so the response can't be verified"
		return s
	}
	r, err := ocsp.ParseResponseForCert(a.o.Staple, leaf, issuer)
	if err != nil {
		s.Status, s.Error = RevError, "the response is not valid for this certificate: "+err.Error()
		return s
	}
	tu := r.ThisUpdate
	s.ThisUpdate = &tu
	if !r.NextUpdate.IsZero() {
		nu := r.NextUpdate
		s.NextUpdate = &nu
	}
	switch r.Status {
	case ocsp.Good:
		s.Status = RevGood
	case ocsp.Revoked:
		s.Status = RevRevoked
		ra := r.RevokedAt
		s.RevokedAt = &ra
		return s
	default:
		s.Status = RevUnknown
	}
	if s.NextUpdate != nil && a.o.Now.After(*s.NextUpdate) {
		s.Status, s.Error = RevError, fmt.Sprintf("the response expired on %s", s.NextUpdate.UTC().Format("2006-01-02 15:04 UTC"))
	} else if a.o.Now.Before(tu.Add(-5 * time.Minute)) {
		s.Status, s.Error = RevError, "the response is dated in the future"
	}
	return s
}

func (a *analyzer) stapleCheck(res *Result) Check {
	c := Check{ID: "ocsp_stapling", Title: "OCSP stapling"}
	s := res.Staple
	leaf := res.Chain[0]
	switch {
	case !s.Present && s.MustStaple:
		c.Status = Fail
		c.Detail = "The certificate requires a stapled OCSP response (Must-Staple), but the server sent none. Browsers that enforce Must-Staple, such as Firefox, will reject the connection."
	case !s.Present && len(leaf.OCSPServers) == 0:
		c.Status = Pass
		c.Detail = "Not stapled. The certificate names no OCSP responder, so there is nothing to staple."
	case !s.Present:
		c.Status = Pass
		c.Detail = "Not stapled. This is optional: clients ask the OCSP responder themselves, or skip the check."
	case s.Status == RevRevoked:
		c.Status = Fail
		c.Detail = "The stapled OCSP response says the leaf certificate is revoked."
		if s.RevokedAt != nil {
			c.Detail = fmt.Sprintf("The stapled OCSP response says the leaf certificate was revoked on %s.", s.RevokedAt.UTC().Format("2006-01-02"))
		}
	case s.Status == RevGood:
		c.Status = Pass
		c.Detail = "The server staples a valid OCSP response saying the leaf certificate is good."
		if s.NextUpdate != nil {
			c.Detail = fmt.Sprintf("The server staples a valid OCSP response saying the leaf certificate is good, until %s.", s.NextUpdate.UTC().Format("2006-01-02 15:04 UTC"))
		}
	default:
		c.Status = Warn
		if s.MustStaple {
			c.Status = Fail
		}
		why := s.Error
		if s.Status == RevUnknown {
			why = "the responder says it doesn't know this certificate"
		}
		c.Detail = "The server staples an OCSP response that clients can't use: " + why + "."
		if s.MustStaple {
			c.Detail += " The certificate requires a usable staple (Must-Staple), so browsers that enforce it will reject the connection."
		}
	}
	return c
}
