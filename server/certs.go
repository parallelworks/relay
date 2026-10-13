package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Certificates serves the relay's TLS certificate and reloads it when the files change, so a
// rotated certificate takes effect without a restart.
type Certificates struct {
	root     *os.Root
	certFile string
	keyFile  string

	mu      sync.Mutex
	certPEM []byte
	keyPEM  []byte
	current atomic.Pointer[tls.Certificate]
}

// LoadCertificates reads a PEM certificate chain and private key from dir.
func LoadCertificates(dir, certFile, keyFile string) (*Certificates, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	c := &Certificates{root: root, certFile: certFile, keyFile: keyFile}
	if _, err := c.Reload(); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return c, nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (c *Certificates) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.current.Load(), nil
}

// Reload rereads the files and, when they changed and parse, serves the new certificate. On error
// the previous certificate stays in use.
func (c *Certificates) Reload() (changed bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	certPEM, err := c.root.ReadFile(c.certFile)
	if err != nil {
		return false, err
	}
	keyPEM, err := c.root.ReadFile(c.keyFile)
	if err != nil {
		return false, err
	}
	if bytes.Equal(certPEM, c.certPEM) && bytes.Equal(keyPEM, c.keyPEM) {
		return false, nil
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return false, fmt.Errorf("server: certificate: %w", err)
	}
	c.certPEM, c.keyPEM = certPEM, keyPEM
	c.current.Store(&cert)
	return true, nil
}

// Watch reloads every interval until ctx ends, logging failures.
func (c *Certificates) Watch(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		changed, err := c.Reload()
		switch {
		case err != nil:
			logger.LogAttrs(ctx, slog.LevelError, "certificate.reload_failed", slog.String("error", err.Error()))
		case changed:
			logger.LogAttrs(ctx, slog.LevelInfo, "certificate.reloaded", slog.Time("not_after", c.current.Load().Leaf.NotAfter))
		}
	}
}

// Close releases the certificate directory.
func (c *Certificates) Close() error {
	return c.root.Close()
}
