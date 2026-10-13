package telemetry

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

// Redacted replaces a removed value.
const Redacted = "[REDACTED]"

var (
	// jws matches a compact JWS or JWT (RFC 7515 §7.1), such as a DPoP proof or a client assertion.
	jws = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*`)
	// credential matches credentials in an Authorization field value (RFC 9110 §11.4).
	credential = regexp.MustCompile(`(?i)\b(DPoP|Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*`)
	// secretKey matches attribute keys whose values are secrets whatever they look like.
	secretKey = regexp.MustCompile(`(?i)(token|authorization|dpop|proof|assertion|secret|password|private_?key)`)
)

// NewLogHandler returns a JSON handler on w at level whose output never carries a credential.
func NewLogHandler(w io.Writer, level slog.Leveler) slog.Handler {
	return Redact(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// Redact wraps h so that attribute values shaped like a token, proof or Authorization credential,
// and every value under a key that names a secret, are replaced with Redacted.
func Redact(h slog.Handler) slog.Handler {
	return redactor{h}
}

type redactor struct{ next slog.Handler }

func (r redactor) Enabled(ctx context.Context, l slog.Level) bool { return r.next.Enabled(ctx, l) }

func (r redactor) Handle(ctx context.Context, rec slog.Record) error { //nolint:gocritic // hugeParam: slog.Handler fixes the signature.
	out := slog.NewRecord(rec.Time, rec.Level, scrub(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redactAttr(a))
		return true
	})
	return r.next.Handle(ctx, out)
}

func (r redactor) WithAttrs(attrs []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		clean[i] = redactAttr(a)
	}
	return redactor{r.next.WithAttrs(clean)}
}

func (r redactor) WithGroup(name string) slog.Handler { return redactor{r.next.WithGroup(name)} }

func redactAttr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		group := v.Group()
		clean := make([]slog.Attr, len(group))
		for i, g := range group {
			clean[i] = redactAttr(g)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(clean...)}
	}
	if secretKey.MatchString(a.Key) && a.Key != "token_id" {
		return slog.String(a.Key, Redacted)
	}
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, scrub(v.String()))
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			return slog.String(a.Key, scrub(err.Error()))
		}
		if s, ok := v.Any().(interface{ String() string }); ok {
			return slog.String(a.Key, scrub(s.String()))
		}
		return slog.String(a.Key, Redacted)
	default:
		return slog.Attr{Key: a.Key, Value: v}
	}
}

func scrub(s string) string {
	if !strings.Contains(s, "eyJ") && !credential.MatchString(s) {
		return s
	}
	s = jws.ReplaceAllString(s, Redacted)
	return credential.ReplaceAllString(s, "$1 "+Redacted)
}
