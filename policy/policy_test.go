package policy

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func mustPolicy(t *testing.T, prefixes []string, exceptions ...string) *Policy {
	t.Helper()
	var ps []netip.Prefix
	for _, s := range prefixes {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	var es []netip.Addr
	for _, s := range exceptions {
		es = append(es, netip.MustParseAddr(s))
	}
	p, err := New(ps, es)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNew(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, nil); err == nil {
		t.Error("empty prefix list accepted")
	}
	if _, err := New([]netip.Prefix{{}}, nil); err == nil {
		t.Error("invalid prefix accepted")
	}
	ok := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if _, err := New(ok, []netip.Addr{{}}); err == nil {
		t.Error("invalid exception accepted")
	}
	if _, err := New(ok, []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}); err == nil {
		t.Error("zoned exception accepted")
	}
}

func TestRejectsHostNames(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"example.com:22", "localhost:22", "host:22", "10.0.0.1", "10.0.0.1:0", "10.0.0.1:65536",
		"[fe80::1%eth0]:22", "010.0.0.1:22", "0x7f.0.0.1:22", "2130706433:22", "", ":22", "[::1]",
	} {
		if _, err := ParseTarget(s); !errors.Is(err, ErrNotIPLiteral) {
			t.Errorf("ParseTarget(%q) err = %v, want ErrNotIPLiteral", s, err)
		}
	}
	for _, s := range []string{"10.0.0.1:22", "[2001:db8::1]:22", "[::ffff:10.0.0.1]:22"} {
		if _, err := ParseTarget(s); err != nil {
			t.Errorf("ParseTarget(%q) = %v", s, err)
		}
	}
}

func TestDeniesOutsidePrefixes(t *testing.T) {
	t.Parallel()
	p := mustPolicy(t, []string{"10.0.0.0/8", "2001:db8::/32"})
	for _, s := range []string{"10.1.2.3:22", "[2001:db8::5]:22"} {
		if err := p.Check(netip.MustParseAddrPort(s)); err != nil {
			t.Errorf("Check(%s) = %v, want allowed", s, err)
		}
	}
	for _, s := range []string{"11.0.0.1:22", "192.168.1.1:22", "[2001:db9::1]:22", "8.8.8.8:443"} {
		if err := p.Check(netip.MustParseAddrPort(s)); !errors.Is(err, ErrDenied) {
			t.Errorf("Check(%s) = %v, want ErrDenied", s, err)
		}
	}
}

func TestDeniesSpecialAddressesInsidePrefix(t *testing.T) {
	t.Parallel()
	p := mustPolicy(t, []string{"0.0.0.0/0", "::/0"}, "169.254.10.10")
	for _, s := range []string{
		"127.0.0.1:22", "127.255.0.1:22", "[::1]:22",
		"169.254.169.254:80", "169.254.0.1:22", "[fe80::1]:22",
		"224.0.0.1:22", "239.1.1.1:22", "[ff02::1]:22", "[ff01::1]:22", "[ff0e::1]:22",
		"0.0.0.0:22", "[::]:22",
		"255.255.255.255:22",
	} {
		if err := p.Check(netip.MustParseAddrPort(s)); !errors.Is(err, ErrDenied) {
			t.Errorf("Check(%s) = %v, want ErrDenied", s, err)
		}
	}
	if err := p.Check(netip.MustParseAddrPort("169.254.10.10:22")); err != nil {
		t.Errorf("listed exception denied: %v", err)
	}
	if err := p.Check(netip.MustParseAddrPort("10.0.0.1:22")); err != nil {
		t.Errorf("ordinary address denied: %v", err)
	}
}

func TestEvaluatesMappedAddressesAsIPv4(t *testing.T) {
	t.Parallel()
	p := mustPolicy(t, []string{"10.0.0.0/8"})
	for _, s := range []string{"[::ffff:127.0.0.1]:22", "[::ffff:169.254.169.254]:80", "[::ffff:11.0.0.1]:22"} {
		if err := p.Check(netip.MustParseAddrPort(s)); !errors.Is(err, ErrDenied) {
			t.Errorf("Check(%s) = %v, want ErrDenied", s, err)
		}
	}
	if err := p.Check(netip.MustParseAddrPort("[::ffff:10.1.1.1]:22")); err != nil {
		t.Errorf("mapped address inside an IPv4 prefix denied: %v", err)
	}
	mapped := mustPolicy(t, []string{"::ffff:10.0.0.0/104"}, "::ffff:127.0.0.1")
	if err := mapped.Check(netip.MustParseAddrPort("10.2.3.4:22")); err != nil {
		t.Errorf("IPv4 address inside a mapped prefix denied: %v", err)
	}
	if err := mapped.Check(netip.MustParseAddrPort("127.0.0.1:22")); err != nil {
		t.Errorf("mapped exception not applied to its IPv4 form: %v", err)
	}
	short := mustPolicy(t, []string{"::ffff:0.0.0.0/64"})
	if err := short.Check(netip.MustParseAddrPort("8.8.8.8:22")); err != nil {
		t.Errorf("mapped prefix shorter than 96 bits should cover all IPv4: %v", err)
	}
}

func TestDialControlRechecksAddress(t *testing.T) {
	t.Parallel()
	p := mustPolicy(t, []string{"10.0.0.0/8"})
	ctx := t.Context()
	if err := p.Control(ctx, "tcp4", "10.0.0.1:22", nil); err != nil {
		t.Errorf("allowed address rejected: %v", err)
	}
	if err := p.Control(ctx, "tcp4", "127.0.0.1:22", nil); !errors.Is(err, ErrDenied) {
		t.Errorf("loopback = %v, want ErrDenied", err)
	}
	if err := p.Control(ctx, "udp4", "10.0.0.1:22", nil); !errors.Is(err, ErrDenied) {
		t.Errorf("udp = %v, want ErrDenied", err)
	}
	if err := p.Control(ctx, "tcp6", "not-an-address", nil); !errors.Is(err, ErrNotIPLiteral) {
		t.Errorf("garbage = %v, want ErrNotIPLiteral", err)
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := ln.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	d := p.Dialer(time.Second)
	if _, dialErr := d.DialContext(ctx, "tcp", ln.Addr().String()); !errors.Is(dialErr, ErrDenied) {
		t.Fatalf("dialing loopback through the policy dialer = %v, want ErrDenied", dialErr)
	}
	open := mustPolicy(t, []string{"10.0.0.0/8"}, "127.0.0.1")
	conn, err := open.Dialer(time.Second).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialing a listed exception: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Error(err)
	}
}

func FuzzParseTarget(f *testing.F) {
	for _, s := range []string{"10.0.0.1:22", "[2001:db8::1]:22", "[::ffff:1.2.3.4]:1", "example.com:22", "[fe80::1%x]:2", ""} {
		f.Add(s)
	}
	p, err := New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ap, err := ParseTarget(s)
		if err != nil {
			return
		}
		if !ap.Addr().IsValid() || ap.Port() == 0 || ap.Addr().Zone() != "" {
			t.Fatalf("ParseTarget(%q) accepted %v", s, ap)
		}
		if p.Check(ap) == nil && !netip.MustParsePrefix("10.0.0.0/8").Contains(ap.Addr().Unmap()) {
			t.Fatalf("Check allowed %v outside the only prefix", ap)
		}
	})
}
