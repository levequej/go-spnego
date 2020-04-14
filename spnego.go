package spnego

import (
	"net"
	"net/http"
	"strings"
)

// Provider is the interface that wraps OS agnostic functions for handling SPNEGO communication
type Provider interface {
	SetSPNEGOHeader(*http.Request) error
}

// BypassCanonicalization is a bool you can set if your target DNS reverse lookup is not implemented correctly
var BypassCanonicalization = false

func canonicalizeHostname(hostname string) (string, error) {

	if BypassCanonicalization {
		return hostname, nil
	}

	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", err
	}
	if len(addrs) < 1 {
		return hostname, nil
	}

	names, err := net.LookupAddr(addrs[0])
	if err != nil {
		return "", err
	}
	if len(names) < 1 {
		return hostname, nil
	}

	return strings.TrimRight(names[0], "."), nil
}
