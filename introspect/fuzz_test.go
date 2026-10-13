package introspect

import (
	"testing"
	"time"
)

func FuzzIntrospectionResponse(f *testing.F) {
	for _, s := range []string{
		`{"active":true,"token_type":"DPoP","sub":"a","aud":"relay","exp":4102444800,"cnf":{"jkt":"j"},"relay_target":"10.0.0.1:22","relay_session":"s"}`,
		`{"active":true,"aud":["relay","x"],"exp":4102444800,"cnf":{"jkt":"j"},"relay_target":"[::1]:22","relay_session":"s"}`,
		`{"active":false}`, `{}`, `[]`, `{"active":true}{}`, `{"exp":1.5,"active":true}`,
	} {
		f.Add([]byte(s))
	}
	now := time.Unix(1_900_000_000, 0)
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := parseResponse(body)
		if err != nil {
			return
		}
		tok, err := validateAccessToken(&r, "relay", now)
		if err != nil {
			return
		}
		if tok.JKT == "" || tok.Session == "" || len(tok.Session) > MaxSessionSize || !tok.Expires.After(now) ||
			!tok.Target.IsValid() || tok.Target.Port() == 0 {
			t.Fatalf("accepted an invalid token %+v from %q", tok, body)
		}
	})
}
