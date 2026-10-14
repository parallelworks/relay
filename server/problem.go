package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/parallelworks/relay/dpop"
)

type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
}

func algorithms() string {
	names := make([]string, len(dpop.Algorithms))
	for i, a := range dpop.Algorithms {
		names[i] = string(a)
	}
	return strings.Join(names, " ")
}

var challengeAlgs = `algs="` + algorithms() + `"`

func (s *Server) reject(ctx context.Context, w http.ResponseWriter, r *http.Request, rej *rejection) {
	attrs := []slog.Attr{
		slog.Int("status", rej.status),
		slog.String("reason", rej.reason),
		slog.String("source", r.RemoteAddr),
		slog.String("authority", r.Host),
	}
	if token, _, crej := credentials(r.Header); crej == nil {
		attrs = append(attrs, slog.String("token_id", TokenID(token)))
	}
	if rej.cause != nil {
		attrs = append(attrs, slog.String("error", rej.cause.Error()))
	}
	s.cfg.Logger.LogAttrs(ctx, slog.LevelInfo, "tunnel.rejected", attrs...)
	s.cfg.Observer.TunnelRejected(ctx, Rejection{Status: rej.status, Reason: rej.reason})

	h := w.Header()
	switch {
	case rej.authError != "":
		h.Set("WWW-Authenticate", dpop.Scheme+` error="`+rej.authError+`", `+challengeAlgs)
	case rej.challenge:
		h.Set("WWW-Authenticate", dpop.Scheme+" "+challengeAlgs)
	}
	if rej.nonce {
		h.Set(dpop.NonceHeaderName, s.cfg.Nonces.Issue())
	}
	if rej.retryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(int(math.Ceil(rej.retryAfter.Seconds()))))
	}
	h.Set("Content-Type", "application/problem+json")
	h.Set("Cache-Control", "no-store")
	if r.ProtoMajor == 1 {
		h.Set("Connection", "close")
	}
	w.WriteHeader(rej.status)
	body, err := json.Marshal(problem{Type: "about:blank", Title: http.StatusText(rej.status), Status: rej.status})
	if err == nil {
		_, err = w.Write(body)
	}
	if err != nil {
		s.cfg.Logger.LogAttrs(ctx, slog.LevelDebug, "tunnel.reject_write_failed", slog.String("error", err.Error()))
	}
}
