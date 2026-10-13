package registration

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/parallelworks/relay/internal/fakeas"
	"github.com/parallelworks/relay/introspect"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

type env struct {
	as    *fakeas.AS
	http  *http.Client
	meta  introspect.Metadata
	store *Store
	dir   string
}

func setup(t *testing.T) *env {
	t.Helper()
	as := fakeas.New(t)
	hc := introspect.NewHTTPClient(as.Pool())
	t.Cleanup(hc.CloseIdleConnections)
	meta, err := introspect.Discover(t.Context(), hc, as.Issuer())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return &env{as: as, http: hc, meta: meta, store: store, dir: dir}
}

func (e *env) request() *Request {
	return &Request{
		Endpoint:           e.meta.RegistrationEndpoint,
		Issuer:             e.meta.Issuer,
		InitialAccessToken: e.as.InitialAccessToken(),
		ClientName:         "test relay",
		SoftwareVersion:    "v0.0.0-test",
	}
}

func TestRegisterThenLoadAndIntrospect(t *testing.T) {
	t.Parallel()
	e := setup(t)
	creds, err := e.store.Register(t.Context(), e.http, e.request())
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := e.store.Load(e.meta.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ClientID != creds.ClientID || loaded.KeyID != creds.KeyID || loaded.KeyID == "" {
		t.Fatalf("loaded %+v, registered %+v", loaded, creds)
	}
	c, err := introspect.NewClient(e.meta, loaded, e.http)
	if err != nil {
		t.Fatal(err)
	}
	tok := e.as.Issue(&fakeas.Grant{
		Subject: "alice", Audience: []string{loaded.ClientID}, JKT: "j", Target: "10.0.0.1:22",
		Session: "s", Expires: time.Now().Add(time.Minute),
	})
	if _, err = c.AccessToken(t.Context(), tok); err != nil {
		t.Fatalf("introspecting with loaded credentials: %v", err)
	}
	reg := e.as.Registrations()[0]
	if reg["token_endpoint_auth_method"] != "private_key_jwt" || reg["software_id"] != SoftwareID ||
		reg["client_name"] != "test relay" || reg["software_version"] != "v0.0.0-test" {
		t.Fatalf("registration metadata %v", reg)
	}
	for _, name := range []string{DefaultKeyName, DefaultClientName} {
		info, statErr := os.Stat(filepath.Join(e.dir, name))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v, want 0600", name, info.Mode().Perm())
		}
	}
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("store left %d files behind, want 2", len(entries))
	}
}

func TestSendsOnlyPublicKey(t *testing.T) {
	t.Parallel()
	e := setup(t)
	if _, err := e.store.Register(t.Context(), e.http, e.request()); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e.as.Registrations()[0]["jwks"])
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("%d keys sent, want 1", len(set.Keys))
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if _, ok := set.Keys[0][private]; ok {
			t.Errorf("registration sent private member %q", private)
		}
	}
}

func TestRefusesPermissiveKeyFile(t *testing.T) {
	t.Parallel()
	e := setup(t)
	if _, err := e.store.Register(t.Context(), e.http, e.request()); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(filepath.Join(e.dir, DefaultKeyName), mode); err != nil {
			t.Fatal(err)
		}
		if _, err := e.store.Load(e.meta.Issuer); !errors.Is(err, ErrPermissiveKeyFile) {
			t.Errorf("mode %v: %v", mode, err)
		}
	}
	if err := os.Chmod(filepath.Join(e.dir, DefaultKeyName), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Load(e.meta.Issuer); err != nil {
		t.Errorf("owner-only read: %v", err)
	}
}

func TestKeyPathCannotEscapeRoot(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	dir := filepath.Join(parent, "store")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	e := setup(t)
	if _, err := e.store.Register(t.Context(), e.http, e.request()); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(e.dir, DefaultKeyName))
	if err != nil {
		t.Fatal(err)
	}
	client, err := os.ReadFile(filepath.Join(e.dir, DefaultClientName))
	if err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G703: the path is built from t.TempDir.
	if err = os.WriteFile(filepath.Join(parent, "outside.pem"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G703: the path is built from t.TempDir.
	if err = os.WriteFile(filepath.Join(dir, DefaultClientName), client, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(parent, "outside.pem"), filepath.Join(dir, "link.pem")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../outside.pem", filepath.Join(parent, "outside.pem"), "link.pem"} {
		s, openErr := Open(dir, Options{KeyName: name})
		if openErr != nil {
			t.Fatal(openErr)
		}
		if _, loadErr := s.Load(e.meta.Issuer); loadErr == nil {
			t.Errorf("key name %q read a file outside the store", name)
		}
		if closeErr := s.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	escaping, err := Open(t.TempDir(), Options{KeyName: "../escape.pem"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := escaping.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := escaping.Register(t.Context(), e.http, e.request()); err == nil {
		t.Error("registration wrote a key outside the store")
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()
	e := setup(t)
	if _, err := e.store.Load(e.meta.Issuer); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("empty store: %v", err)
	}
	if _, err := e.store.Register(t.Context(), e.http, e.request()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Load("https://other.example"); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("other issuer: %v", err)
	}
	if _, err := e.store.Register(t.Context(), e.http, e.request()); !errors.Is(err, ErrAlreadyRegistered) {
		t.Fatalf("second registration: %v", err)
	}

	write := func(name string, data []byte) {
		t.Helper()
		//nolint:gosec // G703: the path is built from t.TempDir.
		if err := os.WriteFile(filepath.Join(e.dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	goodKey, err := os.ReadFile(filepath.Join(e.dir, DefaultKeyName))
	if err != nil {
		t.Fatal(err)
	}
	goodClient, err := os.ReadFile(filepath.Join(e.dir, DefaultClientName))
	if err != nil {
		t.Fatal(err)
	}

	for _, client := range []string{"not json", `{"issuer":"x"}`} {
		write(DefaultClientName, []byte(client))
		if _, err = e.store.Load(e.meta.Issuer); err == nil {
			t.Errorf("client file %q accepted", client)
		}
	}
	write(DefaultClientName, goodClient)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := func(k any) []byte {
		der, marshalErr := x509.MarshalPKCS8PrivateKey(k)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return pem.EncodeToMemory(&pem.Block{Type: pemBlockType, Bytes: der})
	}
	write(DefaultKeyName, pkcs8(rsaKey))
	if creds, loadErr := e.store.Load(e.meta.Issuer); loadErr != nil || creds.Key == nil {
		t.Errorf("RSA key: %v", loadErr)
	}
	for name, data := range map[string][]byte{
		"ed25519":       pkcs8(edKey),
		"not pem":       []byte("garbage"),
		"wrong type":    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}),
		"bad der":       pem.EncodeToMemory(&pem.Block{Type: pemBlockType, Bytes: []byte{1, 2, 3}}),
		"original good": goodKey,
	} {
		write(DefaultKeyName, data)
		_, loadErr := e.store.Load(e.meta.Issuer)
		if (loadErr == nil) != (name == "original good") {
			t.Errorf("%s: %v", name, loadErr)
		}
	}
	if err = os.Remove(filepath.Join(e.dir, DefaultKeyName)); err != nil {
		t.Fatal(err)
	}
	if _, err = e.store.Load(e.meta.Issuer); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing key file: %v", err)
	}
	if err = os.Mkdir(filepath.Join(e.dir, "dir.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(e.dir, Options{ClientName: "dir.json"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := s.Load(e.meta.Issuer); err == nil || errors.Is(err, ErrNotRegistered) {
		t.Errorf("unreadable client file: %v", err)
	}
}

func TestRegisterRejected(t *testing.T) {
	t.Parallel()
	e := setup(t)
	r := e.request()
	r.InitialAccessToken = "wrong"
	if _, err := e.store.Register(t.Context(), e.http, r); err == nil || !strings.Contains(err.Error(), "invalid_token") {
		t.Fatalf("bad initial access token: %v", err)
	}
	reply := func(status int, contentType, body string) {
		e.as.Handle(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", contentType)
			w.WriteHeader(status)
			if _, err := w.Write([]byte(body)); err != nil {
				panic(err)
			}
		})
	}
	cases := []struct {
		status      int
		contentType string
		body        string
	}{
		{http.StatusCreated, "application/json", `{}`},
		{http.StatusCreated, "application/json", `nope`},
		{http.StatusCreated, "text/plain", `{"client_id":"x"}`},
		{http.StatusBadRequest, "application/json", `{}`},
		{http.StatusInternalServerError, "application/json", `oops`},
		{http.StatusCreated, "application/json", `{"client_id":"` + strings.Repeat("x", introspect.MaxResponseSize) + `"}`},
	}
	for _, c := range cases {
		reply(c.status, c.contentType, c.body)
		if _, err := e.store.Register(t.Context(), e.http, e.request()); err == nil {
			t.Errorf("status %d %s %.20q accepted", c.status, c.contentType, c.body)
		}
	}
	r = e.request()
	r.Endpoint = "%zz"
	if _, err := e.store.Register(t.Context(), e.http, r); err == nil {
		t.Error("unparseable endpoint accepted")
	}
	r.Endpoint = "https://127.0.0.1:1/register"
	if _, err := e.store.Register(t.Context(), e.http, r); err == nil {
		t.Error("unreachable endpoint accepted")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing"), Options{}); err == nil {
		t.Error("missing directory opened")
	}
}

func TestRegisterFailsOnReadOnlyStore(t *testing.T) {
	t.Parallel()
	e := setup(t)
	//nolint:gosec // G302: the test makes the store directory read-only on purpose.
	if err := os.Chmod(e.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		//nolint:gosec // G302: restores the directory so t.TempDir can remove it.
		if err := os.Chmod(e.dir, 0o700); err != nil {
			t.Error(err)
		}
	})
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if _, err := e.store.Register(t.Context(), e.http, e.request()); err == nil {
		t.Fatal("registration into a read-only directory succeeded")
	}
}
