package prettylog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"time"
)

func NewTextLogger(out io.Writer, level slog.Level) *slog.Logger {
	return slog.New(NewPrettyHandler(out, &level))
}

type groupOrAttrs struct {
	group string      // group name if non-empty
	attrs []slog.Attr // attrs if non-empty
}

type PrettyHandler struct {
	lev  slog.Leveler
	goas []groupOrAttrs
	mu   *sync.Mutex
	out  io.Writer
}

func NewPrettyHandler(out io.Writer, l *slog.Level) *PrettyHandler {
	h := &PrettyHandler{out: out, mu: &sync.Mutex{}}
	if l != nil {
		h.lev = *l
	}
	if h.lev == nil {
		h.lev = slog.LevelInfo
	}
	return h
}

func (h *PrettyHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.lev.Level()
}

// Append default attributes - time, level, source
func appendDefaultAttrs(r slog.Record) []slog.Attr {
	defaultAttrs := []slog.Attr{
		slog.Time(slog.TimeKey, r.Time),
		slog.Any(slog.LevelKey, r.Level),
	}
	if r.PC != 0 {
		fs := runtime.CallersFrames([]uintptr{r.PC})
		f, _ := fs.Next()
		defaultAttrs = append(defaultAttrs, slog.String(slog.SourceKey, fmt.Sprintf("%s:%d", f.File, f.Line)))
	}

	return defaultAttrs
}

func (h *PrettyHandler) Handle(ctx context.Context, r slog.Record) error {
	buf := make([]byte, 0, 1024)

	buf = append(buf, "----- DEFAULT INFO -----\n"...)
	defaultAttrs := appendDefaultAttrs(r)
	// Add default attributes to the buffer
	for _, attr := range defaultAttrs {
		buf = h.appendAttr(buf, attr, 0)
	}

	// Append message
	buf = h.appendAttr(buf, slog.String(slog.MessageKey, r.Message), 0)

	indentLevel := 0
	// Handle state from WithGroup and WithAttrs.
	goas := h.goas
	if r.NumAttrs() == 0 {
		// If the record has no Attrs, remove groups at the end of the list; they are empty.
		for len(goas) > 0 && goas[len(goas)-1].group != "" {
			goas = goas[:len(goas)-1]
		}
	} else {
		buf = append(buf, "----- CUSTOM INFO -----\n"...)
	}

	for _, goa := range goas {
		if goa.group != "" {
			buf = fmt.Appendf(buf, "%*s%s:\n", indentLevel*4, "", goa.group)
			indentLevel++
		} else {
			for _, a := range goa.attrs {
				buf = h.appendAttr(buf, a, indentLevel)
			}
		}
	}
	r.Attrs(func(a slog.Attr) bool {
		buf = h.appendAttr(buf, a, indentLevel)
		return true
	})

	// Colorize based on log level
	colorCode, ok := levelColors[r.Level]
	if ok {
		buf = []byte(colorize(colorCode, string(buf)))
	}

	// End log message
	buf = append(buf, "---\n"...)

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.out.Write(buf)

	return err
}

func (h *PrettyHandler) appendAttr(buf []byte, a slog.Attr, indentLevel int) []byte {
	// Resolve the Attr's value before doing anything else.
	a.Value = a.Value.Resolve()
	// Ignore empty Attrs.
	if a.Equal(slog.Attr{}) {
		return buf
	}
	// Indent 4 spaces per level.
	buf = fmt.Appendf(buf, "%*s", indentLevel*4, "")
	switch a.Value.Kind() {
	case slog.KindString:
		// Quote string values, to make them easy to parse.
		buf = fmt.Appendf(buf, "%s: %q\n", a.Key, a.Value.String())
	case slog.KindTime:
		// Write times in a standard way, without the monotonic time.
		loc := time.FixedZone("UTC+3", 3*60*60)
		t := a.Value.Time().In(loc)
		buf = fmt.Appendf(buf, "%s: %s\n", a.Key, t.Format("2006-01-02 15:04:05"))
	case slog.KindGroup:
		attrs := a.Value.Group()
		// Ignore empty groups.
		if len(attrs) == 0 {
			return buf
		}
		// If the key is non-empty, write it out and indent the rest of the attrs.
		// Otherwise, inline the attrs.
		if a.Key != "" {
			buf = fmt.Appendf(buf, "%s:\n", a.Key)
			indentLevel++
		}
		for _, ga := range attrs {
			buf = h.appendAttr(buf, ga, indentLevel)
		}
	default:
		buf = fmt.Appendf(buf, "%s: %s\n", a.Key, a.Value)
	}
	return buf
}

func (h *PrettyHandler) withGroupOrAttrs(goa groupOrAttrs) *PrettyHandler {
	hNew := *h
	hNew.goas = make([]groupOrAttrs, len(h.goas)+1)
	copy(hNew.goas, h.goas)
	hNew.goas[len(hNew.goas)-1] = goa
	return &hNew
}

func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return h.withGroupOrAttrs(groupOrAttrs{group: name})
}

func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return h.withGroupOrAttrs(groupOrAttrs{attrs: attrs})
}
