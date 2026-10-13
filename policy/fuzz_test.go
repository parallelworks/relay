package policy

import (
	"net/netip"
	"testing"
)

func FuzzParseTarget(f *testing.F) {
	for _, s := range []string{"10.0.0.1:22", "[2001:db8::1]:22", "[::ffff:1.2.3.4]:1", "example.com:22", "[fe80::1%x]:2", ""} {
		f.Add(s)
	}
	allowed := netip.MustParsePrefix("10.0.0.0/8")
	p, err := New([]netip.Prefix{allowed}, nil)
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
		if p.Check(ap) == nil && !allowed.Contains(ap.Addr().Unmap()) {
			t.Fatalf("Check allowed %v outside the only prefix", ap)
		}
	})
}
