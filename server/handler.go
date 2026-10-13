package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/introspect"
	"github.com/parallelworks/relay/policy"
	"github.com/parallelworks/relay/session"
	"github.com/parallelworks/relay/tunnel"
)

const (
	reasonClosing           = "closing"
	reasonCapacity          = "capacity"
	reasonSourceLimit       = "source_limit"
	reasonRateLimited       = "rate_limited"
	reasonMethod            = "method"
	reasonAuthority         = "authority"
	reasonDuplicateField    = "duplicate_field"
	reasonMissingToken      = "missing_token"
	reasonScheme            = "scheme"
	reasonMalformedToken    = "malformed_token"
	reasonMissingProof      = "missing_proof"
	reasonNonce             = "nonce"
	reasonProof             = "proof"
	reasonReplayCacheFull   = "replay_cache_full"
	reasonInactiveToken     = "inactive_token"
	reasonUnavailable       = "authorization_server_unavailable"
	reasonKeyBinding        = "key_binding"
	reasonTargetMismatch    = "target_mismatch"
	reasonEgressDenied      = "egress_denied"
	reasonTargetUnreachable = "target_unreachable"
	reasonResponse          = "response"
)

// Reasons a tunnel closed, reported in Closed.Reason.
const (
	CloseEOF             = "eof"
	CloseRevoked         = "revoked"
	CloseSubjectMismatch = "subject_mismatch"
	CloseExpired         = "expired"
	CloseUnverified      = "session_unverified"
	CloseIdle            = "idle"
	ClosePanic           = "panic"
	CloseShutdown        = "shutdown"
	CloseError           = "error"
)

const (
	retryAfterBusy        = time.Second
	retryAfterUnavailable = 5 * time.Second
)

const (
	authInvalidToken = "invalid_token"
	authInvalidProof = "invalid_dpop_proof"
	authUseNonce     = "use_dpop_nonce"
)

type rejection struct {
	status     int
	reason     string
	authError  string
	challenge  bool
	nonce      bool
	retryAfter time.Duration
	cause      error
}

type grant struct {
	token  introspect.Token
	target netip.AddrPort
}

// ServeHTTP handles one CONNECT request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	src := sourceOf(r.RemoteAddr)
	if wait, ok := s.failures.allow(src, time.Now()); !ok {
		s.reject(ctx, w, r, &rejection{status: http.StatusTooManyRequests, reason: reasonRateLimited, retryAfter: wait})
		return
	}
	ctx, leave, rej := s.enter(ctx, src)
	if rej != nil {
		s.reject(ctx, w, r, rej)
		return
	}
	defer leave()

	g, rej := s.authorize(ctx, r)
	if rej != nil {
		if rej.status == http.StatusUnauthorized && !rej.nonce {
			s.failures.fail(src, time.Now())
		}
		s.reject(ctx, w, r, rej)
		return
	}
	s.relay(ctx, w, r, &g)
}

func (s *Server) authorize(ctx context.Context, r *http.Request) (grant, *rejection) {
	if r.Method != http.MethodConnect || r.Header.Get(":protocol") != "" {
		return grant{}, &rejection{status: http.StatusBadRequest, reason: reasonMethod}
	}
	if r.URL.Path != "" || r.URL.RawQuery != "" || r.URL.Scheme != "" {
		return grant{}, &rejection{status: http.StatusBadRequest, reason: reasonAuthority}
	}
	authority := r.URL.Host
	target, err := policy.ParseTarget(authority)
	if err != nil {
		return grant{}, &rejection{status: http.StatusBadRequest, reason: reasonAuthority, cause: err}
	}
	token, proof, rej := credentials(r.Header)
	if rej != nil {
		return grant{}, rej
	}
	verified, err := s.cfg.Verifier.Verify(dpop.Request{
		Method:      http.MethodConnect,
		URI:         dpop.TargetURI(authority),
		AccessToken: token,
		Proof:       proof,
	})
	switch {
	case err == nil:
	case errors.Is(err, dpop.ErrNonce) && s.cfg.Nonces != nil:
		return grant{}, &rejection{status: http.StatusUnauthorized, reason: reasonNonce, authError: authUseNonce, nonce: true, cause: err}
	case errors.Is(err, dpop.ErrReplayCacheFull):
		return grant{}, &rejection{status: http.StatusServiceUnavailable, reason: reasonReplayCacheFull, retryAfter: retryAfterBusy, cause: err}
	default:
		return grant{}, &rejection{status: http.StatusUnauthorized, reason: reasonProof, authError: authInvalidProof, cause: err}
	}

	ictx, cancel := context.WithTimeout(ctx, s.limits.IntrospectionTimeout)
	tok, err := s.cfg.Introspector.AccessToken(ictx, token)
	cancel()
	switch {
	case err == nil:
	case errors.Is(err, introspect.ErrUnavailable) || errors.Is(err, context.DeadlineExceeded):
		return grant{}, &rejection{status: http.StatusServiceUnavailable, reason: reasonUnavailable, retryAfter: retryAfterUnavailable, cause: err}
	default:
		return grant{}, &rejection{status: http.StatusUnauthorized, reason: reasonInactiveToken, authError: authInvalidToken, cause: err}
	}
	if err := verified.Bound(tok.JKT); err != nil {
		return grant{}, &rejection{status: http.StatusUnauthorized, reason: reasonKeyBinding, authError: authInvalidToken, cause: err}
	}
	if tok.Target != target {
		return grant{}, &rejection{status: http.StatusForbidden, reason: reasonTargetMismatch}
	}
	if err := s.cfg.Policy.Check(target); err != nil {
		return grant{}, &rejection{status: http.StatusForbidden, reason: reasonEgressDenied, cause: err}
	}
	return grant{token: tok, target: target}, nil
}

func credentials(h http.Header) (token, proof string, rej *rejection) {
	auth := h.Values("Authorization")
	proofs := h.Values(dpop.HeaderName)
	if len(auth) > 1 || len(proofs) > 1 {
		return "", "", &rejection{status: http.StatusBadRequest, reason: reasonDuplicateField}
	}
	if len(auth) == 0 {
		return "", "", &rejection{status: http.StatusUnauthorized, reason: reasonMissingToken, challenge: true}
	}
	scheme, rest, _ := strings.Cut(auth[0], " ")
	if !strings.EqualFold(scheme, dpop.Scheme) {
		return "", "", &rejection{status: http.StatusUnauthorized, reason: reasonScheme, authError: authInvalidToken}
	}
	token = strings.TrimLeft(rest, " ")
	if !isToken68(token) {
		return "", "", &rejection{status: http.StatusUnauthorized, reason: reasonMalformedToken, authError: authInvalidToken}
	}
	if len(proofs) == 0 {
		return "", "", &rejection{status: http.StatusUnauthorized, reason: reasonMissingProof, authError: authInvalidProof}
	}
	return token, proofs[0], nil
}

// isToken68 reports whether s matches token68 (RFC 9110 §11.2).
func isToken68(s string) bool {
	body := strings.TrimRight(s, "=")
	if body == "" {
		return false
	}
	for _, c := range []byte(body) {
		alnum := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
		if !alnum && !strings.ContainsRune("-._~+/", rune(c)) {
			return false
		}
	}
	return true
}

func (s *Server) relay(ctx context.Context, w http.ResponseWriter, r *http.Request, g *grant) {
	sctx, sess, stop := s.cfg.Sessions.Start(ctx, g.token.Subject, g.token.Session, g.target)
	defer stop()

	conn, err := s.dialer.DialContext(sctx, "tcp", g.target.String())
	if err != nil {
		s.reject(ctx, w, r, &rejection{status: http.StatusBadGateway, reason: reasonTargetUnreachable, cause: err})
		return
	}
	target := conn.(*net.TCPConn)

	client, err := accept(w, r)
	if err != nil {
		s.cfg.Logger.LogAttrs(ctx, slog.LevelWarn, "tunnel.response_failed", slog.String("error", err.Error()))
		s.cfg.Observer.TunnelRejected(ctx, Rejection{Status: http.StatusOK, Reason: reasonResponse})
		if cerr := target.Close(); cerr != nil {
			s.cfg.Logger.LogAttrs(ctx, slog.LevelDebug, "tunnel.close_failed", slog.String("error", cerr.Error()))
		}
		return
	}

	t := Tunnel{ID: sess.ID, Subject: g.token.Subject, Target: g.target, Protocol: r.Proto}
	s.cfg.Observer.TunnelOpened(ctx, t)
	var counters tunnel.Counters
	err = tunnel.Pipe(sctx, client, target, &counters, tunnel.Options{
		IdleTimeout: s.limits.IdleTimeout,
		OnPanic: func(recovered any) {
			s.cfg.Logger.LogAttrs(ctx, slog.LevelError, "tunnel.panic", slog.Uint64("tunnel", t.ID), slog.Any("recovered", recovered))
		},
	})
	c := Closed{
		Tunnel:     t,
		Reason:     closeReason(err),
		Upstream:   counters.Upstream.Load(),
		Downstream: counters.Downstream.Load(),
		Duration:   time.Since(sess.Started),
	}
	attrs := []slog.Attr{
		slog.Uint64("tunnel", t.ID),
		slog.String("sub", t.Subject),
		slog.String("target", t.Target.String()),
		slog.String("protocol", t.Protocol),
		slog.Group("bytes", slog.Int64("upstream", c.Upstream), slog.Int64("downstream", c.Downstream)),
		slog.Duration("duration", c.Duration),
		slog.String("close_reason", c.Reason),
	}
	if c.Reason == CloseError {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	s.cfg.Logger.LogAttrs(ctx, slog.LevelInfo, "tunnel.closed", attrs...)
	s.cfg.Observer.TunnelClosed(ctx, &c)
}

func closeReason(err error) string {
	switch {
	case err == nil, errors.Is(err, errStreamEnded):
		return CloseEOF
	case errors.Is(err, session.ErrRevoked):
		return CloseRevoked
	case errors.Is(err, session.ErrSubjectMismatch):
		return CloseSubjectMismatch
	case errors.Is(err, session.ErrExpired):
		return CloseExpired
	case errors.Is(err, session.ErrNoAnswer):
		return CloseUnverified
	case errors.Is(err, tunnel.ErrIdle):
		return CloseIdle
	case errors.Is(err, tunnel.ErrPanic):
		return ClosePanic
	case errors.Is(err, ErrClosed):
		return CloseShutdown
	default:
		return CloseError
	}
}
