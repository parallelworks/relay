// Package policy decides which addresses the relay may dial.
package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

var (
	// ErrNotIPLiteral reports a target that is not an IP literal and port.
	ErrNotIPLiteral = errors.New("target is not an IP literal and port")
	// ErrDenied reports a target outside the egress policy.
	ErrDenied = errors.New("target denied by egress policy")
)

var broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// Policy is an egress allowlist of prefixes with fixed denials for special-purpose addresses.
type Policy struct {
	prefixes   []netip.Prefix
	exceptions map[netip.Addr]struct{}
}

// New returns a policy allowing addresses inside prefixes. Special-purpose addresses are denied
// even inside a prefix unless listed in exceptions.
func New(prefixes []netip.Prefix, exceptions []netip.Addr) (*Policy, error) {
	if len(prefixes) == 0 {
		return nil, errors.New("policy needs at least one prefix")
	}
	p := &Policy{exceptions: make(map[netip.Addr]struct{}, len(exceptions))}
	for _, pfx := range prefixes {
		if !pfx.IsValid() {
			return nil, fmt.Errorf("invalid prefix %v", pfx)
		}
		p.prefixes = append(p.prefixes, unmapPrefix(pfx).Masked())
	}
	for _, a := range exceptions {
		if !a.IsValid() || a.Zone() != "" {
			return nil, fmt.Errorf("invalid exception %v", a)
		}
		p.exceptions[a.Unmap()] = struct{}{}
	}
	return p, nil
}

func unmapPrefix(p netip.Prefix) netip.Prefix {
	if !p.Addr().Is4In6() {
		return p
	}
	bits := max(p.Bits()-96, 0)
	return netip.PrefixFrom(p.Addr().Unmap(), bits)
}

// ParseTarget parses an authority of the form ip:port or [ip]:port. Host names are rejected.
func ParseTarget(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil || ap.Addr().Zone() != "" || ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: %q", ErrNotIPLiteral, s)
	}
	return ap, nil
}

// Check returns nil when the policy allows dialing target.
func (p *Policy) Check(target netip.AddrPort) error {
	addr := target.Addr().Unmap()
	if _, ok := p.exceptions[addr]; ok {
		return nil
	}
	if special(addr) {
		return fmt.Errorf("%w: %v is a special-purpose address", ErrDenied, addr)
	}
	for _, pfx := range p.prefixes {
		if pfx.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("%w: %v is outside every allowed prefix", ErrDenied, addr)
}

func special(a netip.Addr) bool {
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || a == broadcast
}

// Control is a net.Dialer.ControlContext hook that re-checks the address a socket connects to.
func (p *Policy) Control(_ context.Context, network, address string, _ syscall.RawConn) error {
	if network != "tcp4" && network != "tcp6" {
		return fmt.Errorf("%w: network %q", ErrDenied, network)
	}
	ap, err := ParseTarget(address)
	if err != nil {
		return err
	}
	return p.Check(ap)
}

// Dialer returns a TCP dialer whose sockets are checked against the policy as they connect.
func (p *Policy) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, ControlContext: p.Control}
}
