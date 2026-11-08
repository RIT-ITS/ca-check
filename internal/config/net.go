package config

import (
	"net"
	"strings"
)

func splitHostPortDefault(s, defPort string) (string, string, error) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p, nil
	}
	return strings.Trim(s, "[]"), defPort, nil
}

func joinHostPort(h, p string) string { return net.JoinHostPort(h, p) }
