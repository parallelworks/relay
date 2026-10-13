package client

import (
	"strings"
	"testing"
	"time"
)

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func FuzzChallengeError(f *testing.F) {
	f.Add("invalid_token", "ES256 ES384 PS256", `DPoP error="invalid_token"`)
	f.Add(`a"b\c`, `x,y="z"`, `DPoP error="a\"b`)
	f.Add("", "", `Basic realm="x"`)
	f.Fuzz(func(t *testing.T, code, other, raw string) {
		challengeError([]string{raw})
		h := "DPoP algs=" + quote(other) + ", error=" + quote(code)
		if got := challengeError([]string{h}); got != code {
			t.Fatalf("challengeError(%q) = %q, want %q", h, got, code)
		}
	})
}

func FuzzRetryAfter(f *testing.F) {
	f.Add("120")
	f.Add("Wed, 21 Oct 2015 07:28:00 GMT")
	f.Add("-5")
	now := time.Unix(1_700_000_000, 0)
	f.Fuzz(func(t *testing.T, v string) {
		if d := retryAfter(v, now); d < 0 {
			t.Fatalf("retryAfter(%q) = %v", v, d)
		}
	})
}
