package testpki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestLeafVerifiesAgainstPool(t *testing.T) {
	t.Parallel()
	ca := New(t)
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		cfg := ca.ServerConfig(t)
		leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: ca.Pool()}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Error("server config allows TLS below 1.3")
		}
	}
	other := New(t)
	leaf, err := x509.ParseCertificate(other.Leaf(t, "localhost").Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "localhost", Roots: ca.Pool()}); err == nil {
		t.Error("leaf from another CA verified")
	}
}

type recordingTB struct {
	testing.TB
	fatal bool
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Fatal(...any) {
	r.fatal = true
}

func TestMustFailsTheTest(t *testing.T) {
	t.Parallel()
	r := &recordingTB{}
	must(r, nil)
	if r.fatal {
		t.Fatal("must failed on a nil error")
	}
	must(r, errors.New("boom"))
	if !r.fatal {
		t.Fatal("must did not fail on an error")
	}
}

func TestLeafPEMIsAKeyPair(t *testing.T) {
	t.Parallel()
	ca := New(t)
	certPEM, keyPEM := ca.LeafPEM(t, "127.0.0.1")
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pair.Leaf.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: ca.Pool()}); err != nil {
		t.Fatal(err)
	}
}

func TestCertPEMMatchesPool(t *testing.T) {
	t.Parallel()
	ca := New(t)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("CertPEM did not parse")
	}
	if !pool.Equal(ca.Pool()) {
		t.Fatal("CertPEM differs from the pool")
	}
}
