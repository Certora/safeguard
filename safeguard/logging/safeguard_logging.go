package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// What follows is a *lot* of boilerplate to get reasonable looking log messages
// the default text handler provided by the slog package formats everything as a seuence of `k=v`,
// the only way I can tell to get something better looking is to implement the handler API ourselves
// a lot of this is cargo-culted from the slog TestHandler package

type detectorHandler struct {
	// mutex to protect writer
	m *sync.Mutex
	// level to log at, always points to top level levelVar
	levelVar *slog.LevelVar
	// pre-formatted attributes that have been added via WithAttr
	attr string
	// pre-formatted group prefix, used to "qualify" added on later. This is never actually used here
	groupPrefix string
	// output location for the log. Currently just stdout
	writer io.Writer
}

// new handler, should really only be called once
func GetHandler(lv *slog.LevelVar) *detectorHandler {
	return &detectorHandler{
		m:           &sync.Mutex{},
		levelVar:    lv,
		attr:        "",
		groupPrefix: "",
		writer:      os.Stdout,
	}
}

func (h *detectorHandler) Enabled(c context.Context, l slog.Level) bool {
	s := h.levelVar.Level()
	return l >= s
}

// Cargo-culted from the TextHandler. The behavior of groups is not
// well documented: as AFAICT, if you do `s.WithGroup("x").WithAttr("y", whatever)`
// then the attribute in the output will be `x.y=whatever`, AKA namespacing for
// attributes.
// This attempts to implement something faithful to this fuzzy spec,
// but since we never use groups, I don't claim this is right
func (h *detectorHandler) WithGroup(s string) slog.Handler {
	if s == "" {
		return h
	}
	newGroup := h.groupPrefix
	if len(h.groupPrefix) != 0 {
		newGroup += "."
	}
	newGroup += s
	return &detectorHandler{
		m:           h.m,
		levelVar:    h.levelVar,
		attr:        h.attr,
		groupPrefix: newGroup,
		writer:      h.writer,
	}
}

// Adds "attributes" that are always included with the log messages
// logged on the output. The attributes added this way are included as
// parentheticals after the main log message and per-message attributes.
// Also, pool ids are internally trucated, to be 0xabfed...12345 to avoid filling
// up the screen
func (h *detectorHandler) WithAttrs(s []slog.Attr) slog.Handler {
	var b strings.Builder
	b.WriteString(h.attr)
	if b.Len() != 0 {
		b.WriteByte(' ')
	}
	needDot := len(h.groupPrefix) > 0
	for _, r := range s {
		if needDot {
			b.WriteString(h.groupPrefix)
			b.WriteByte('.')
		}
		b.WriteString(r.Key)
		b.WriteByte('=')
		if asHash, ok := r.Value.Any().(common.Hash); ok && r.Key == "pool" {
			hashString := asHash.Hex()
			hashFmt := hashString[0:10] + "..." + hashString[56:66]
			b.WriteString(hashFmt)
		} else {
			b.WriteString(r.Value.String())
		}
	}
	return &detectorHandler{
		m:           h.m,
		attr:        b.String(),
		levelVar:    h.levelVar,
		groupPrefix: h.groupPrefix,
		writer:      h.writer,
	}
}

// no, this is not a bug, this is what a formatting string looks like in Go
const formatString = "[01-02|15:04:05.000]"

func (h *detectorHandler) Handle(c context.Context, r slog.Record) error {
	var b strings.Builder
	level := r.Level.String()
	// these write functions return an error, but the Builder API promises
	// its always null
	b.WriteString(level)
	b.WriteByte(' ')
	var t time.Time
	// is there a better way to check for the zero time? I don't know!
	if r.Time != t {
		b.WriteString(r.Time.Format(formatString))
		b.WriteByte(' ')
	}
	b.WriteString(r.Message)
	hasGroup := len(h.groupPrefix) != 0
	r.Attrs(func(a slog.Attr) bool {
		if a.Equal(slog.Attr{}) {
			return true
		}
		// we *know* we don't create this attribute, so just ignore it
		if a.Value.Kind() == slog.KindGroup {
			// nah
			return false
		}
		b.WriteByte(' ')
		if hasGroup {
			b.WriteString(h.groupPrefix)
			b.WriteByte('.')
		}
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.String())
		return true
	})
	// add the pre-formatted attributes in a parenthetical later in the log message
	if len(h.attr) != 0 {
		b.WriteByte(' ')
		b.WriteByte('(')
		b.WriteString(h.attr)
		b.WriteByte(')')
	}
	b.WriteByte('\n')
	h.m.Lock()
	defer h.m.Unlock()
	h.writer.Write([]byte(b.String()))
	return nil
}
