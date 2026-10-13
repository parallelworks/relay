package client

import (
	"net/http"
	"testing"
	"time"
)

func TestChallengeError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{`DPoP error="invalid_token", algs="ES256 ES384 PS256"`}, "invalid_token"},
		{[]string{`DPoP algs="ES256", error="use_dpop_nonce"`}, "use_dpop_nonce"},
		{[]string{`dpop ERROR=invalid_dpop_proof, algs="ES256"`}, "invalid_dpop_proof"},
		{[]string{`DPoP error="a\"b"`}, `a"b`},
		{[]string{`DPoP error="unterminated`}, "unterminated"},
		{[]string{`Bearer error="invalid_token"`, `DPoP algs="ES256"`}, ""},
		{[]string{`DPoP algs="ES256"`}, ""},
		{[]string{`DPoP garbage`}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := challengeError(c.in); got != c.want {
			t.Errorf("challengeError(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"":     0,
		"7":    7 * time.Second,
		"-1":   0,
		"soon": 0,
		now.Add(90 * time.Second).Format(http.TimeFormat): 90 * time.Second,
		now.Add(-time.Hour).Format(http.TimeFormat):       0,
	}
	for in, want := range cases {
		if got := retryAfter(in, now); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestRefusedWithoutProblemDetails(t *testing.T) {
	t.Parallel()
	e := refused(&response{StatusCode: http.StatusBadGateway, Header: http.Header{"Content-Type": {"text/plain"}}, Body: []byte(`{"title":"ignored"}`)})
	if e.Title != "Bad Gateway" || e.AuthError != "" || e.RetryAfter != 0 {
		t.Fatalf("refused = %+v", e)
	}
	e = refused(&response{StatusCode: http.StatusForbidden, Header: http.Header{"Content-Type": {"application/problem+json"}}, Body: []byte(`{"title":"Custom"}`)})
	if e.Title != "Custom" {
		t.Fatalf("refused = %+v", e)
	}
}

func TestCloseIdleConnectionsBeforeUse(t *testing.T) {
	t.Parallel()
	(&Dialer{}).CloseIdleConnections()
}
