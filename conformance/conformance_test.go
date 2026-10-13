package conformance_test

import (
	"crypto/rand"
	"crypto/x509"
	"net/netip"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/parallelworks/relay/conformance"
	"github.com/parallelworks/relay/internal/fakeas"
	"github.com/parallelworks/relay/internal/relaytest"
)

// net/http keeps a connection it closes after a response for a fixed 500 ms, to avoid a TCP reset.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, goleak.IgnoreAnyFunction("net/http.(*conn).closeWriteAndWait"))
}

type env struct {
	*relaytest.Env
}

func (e env) Relay() (string, *x509.CertPool) { return e.Addr, e.Roots }

func (e env) Target() netip.AddrPort { return e.Echo }

func (e env) RevocationDeadline() time.Duration { return 5 * time.Second }

func (e env) Issue(_ testing.TB, g conformance.Grant) (token string, revoke func()) {
	session := "session-" + rand.Text()
	token = e.AS.Issue(&fakeas.Grant{
		Subject:  g.Subject,
		Audience: []string{e.ClientID},
		JKT:      g.JKT,
		Target:   g.Target.String(),
		Session:  session,
		Expires:  time.Now().Add(time.Minute),
	})
	return token, func() { e.AS.SetSession(session, g.Subject, false) }
}

func TestConformance(t *testing.T) {
	t.Parallel()
	conformance.Run(t, env{relaytest.Start(t, &relaytest.Options{SessionInterval: 50 * time.Millisecond})})
}

func TestConformanceWithNonces(t *testing.T) {
	t.Parallel()
	conformance.Run(t, env{relaytest.Start(t, &relaytest.Options{Nonces: true, SessionInterval: 50 * time.Millisecond})})
}
