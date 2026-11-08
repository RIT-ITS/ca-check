// Package netguard decides which target IPs a given client may probe.
package netguard

import (
	"fmt"
	"net/netip"
)

// builtinPrivate are ranges that require the client to be in the
// private-target allowlist.
var builtinPrivate = mustPrefixes(
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"127.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15",
	"::1/128", "fc00::/7",
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// Guard holds the target policy.
type Guard struct {
	Deny                 []netip.Prefix // never testable
	Private              []netip.Prefix // testable only by PrivateClients
	PrivateClients       []netip.Prefix
	OverrideClients      []netip.Prefix // empty = everyone may override
	AllowRequestOverride bool
}

// New builds a Guard; extraPrivate is appended to the built-in private ranges.
func New(deny, extraPrivate, privateClients, overrideClients []netip.Prefix, allowOverride bool) *Guard {
	priv := append(append([]netip.Prefix{}, builtinPrivate...), extraPrivate...)
	return &Guard{Deny: deny, Private: priv, PrivateClients: privateClients,
		OverrideClients: overrideClients, AllowRequestOverride: allowOverride}
}

func contains(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// CheckTarget returns nil if client may probe target, else a reason.
func (g *Guard) CheckTarget(client, target netip.Addr) error {
	target = target.Unmap()
	if !target.IsValid() {
		return fmt.Errorf("invalid address")
	}
	if contains(g.Deny, target) {
		return fmt.Errorf("%s is in the target denylist", target)
	}
	if target.IsUnspecified() || target.IsMulticast() || target.IsLinkLocalUnicast() || target.IsLinkLocalMulticast() {
		return fmt.Errorf("%s is not a routable unicast address", target)
	}
	if contains(g.Private, target) || target.IsLoopback() || target.IsPrivate() {
		if !contains(g.PrivateClients, client) {
			return fmt.Errorf("%s is a private address and your client IP is not permitted to test private targets", target)
		}
	}
	return nil
}

// CheckOverride reports whether client may supply connectIPs.
func (g *Guard) CheckOverride(client netip.Addr) error {
	if !g.AllowRequestOverride {
		return fmt.Errorf("IP override is disabled on this server")
	}
	if len(g.OverrideClients) > 0 && !contains(g.OverrideClients, client) {
		return fmt.Errorf("your client IP is not permitted to override DNS")
	}
	return nil
}

// OverrideAllowedFor is a non-error convenience for the UI config endpoint.
func (g *Guard) OverrideAllowedFor(client netip.Addr) bool { return g.CheckOverride(client) == nil }
