package dpop

import "testing"

func FuzzVerify(f *testing.F) {
	key, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	p, err := NewProver(key)
	if err != nil {
		f.Fatal(err)
	}
	uri := TargetURI("10.0.0.1:22")
	seed, err := p.Proof("CONNECT", uri, "token", "")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add("e30.e30.")
	f.Add("..")
	v := NewVerifier(Options{})
	f.Fuzz(func(t *testing.T, proof string) {
		got, err := v.Verify(Request{Method: "CONNECT", URI: uri, AccessToken: "token", Proof: proof})
		if err == nil && got.JKT == "" {
			t.Fatal("accepted proof without a thumbprint")
		}
	})
}

func FuzzNormalizeURI(f *testing.F) {
	for _, s := range []string{"https://10.0.0.1:22", "https://[::1]:443/", "HTTP://A:80", "%zz", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := normalizeURI(s)
		if !ok {
			return
		}
		again, ok := normalizeURI(n)
		if !ok || again != n {
			t.Fatalf("normalization of %q is not idempotent: %q then %q", s, n, again)
		}
	})
}
