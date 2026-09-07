package progress

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func newTestBar(w *bytes.Buffer, tty bool) *Bar {
	return &Bar{w: w, tty: tty, start: time.Now(), lastPct: -1}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{2_899_102_924, "2.7 GB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestETA(t *testing.T) {
	if got := eta(0, 100, 0); got != "--:--" {
		t.Errorf("eta with no rate = %q, want --:--", got)
	}
	if got := eta(100, 100, 10); got != "--:--" {
		t.Errorf("eta when finished = %q, want --:--", got)
	}
	if got := eta(0, 120, 1); got != "02:00" {
		t.Errorf("eta = %q, want 02:00", got)
	}
	if got := eta(0, 7325, 1); !strings.HasPrefix(got, "2:") {
		t.Errorf("eta over an hour = %q, want hours:minutes:seconds", got)
	}
}

// A non-terminal writer must not emit carriage returns: a CI log or a redirect
// would become one unreadable line kilometres wide.
func TestNonTerminalPrintsDeciles(t *testing.T) {
	var buf bytes.Buffer
	b := newTestBar(&buf, false)

	for i := range 101 {
		b.Update(int64(i), 100)
	}

	out := buf.String()
	if strings.Contains(out, "\r") {
		t.Error("carriage return written to a non-terminal")
	}
	if n := strings.Count(out, "\n"); n > 12 {
		t.Errorf("%d lines for one download, want roughly one per decile", n)
	}
	if !strings.Contains(out, "100%") {
		t.Error("completion was never reported")
	}
}

func TestTerminalRedrawsInPlace(t *testing.T) {
	var buf bytes.Buffer
	b := newTestBar(&buf, true)

	b.Update(25, 100)
	b.Update(50, 100)

	out := buf.String()
	if strings.Count(out, "\r") != 2 {
		t.Errorf("expected one carriage return per update, got %q", out)
	}
	if strings.Contains(out, "\n") {
		t.Error("a newline was written mid-download, so the bar will not redraw in place")
	}
	if !strings.Contains(out, "50%") {
		t.Errorf("percentage missing from %q", out)
	}
}

func TestNoTotalSkipsPercentage(t *testing.T) {
	var buf bytes.Buffer
	b := newTestBar(&buf, true)
	b.Update(2048, 0)
	out := buf.String()
	if strings.Contains(out, "%") {
		t.Errorf("a percentage was shown without a known total: %q", out)
	}
	if !strings.Contains(out, "2.0 KB") {
		t.Errorf("the byte count is missing from %q", out)
	}
}

func TestDoneIsQuietWhenNothingWasDrawn(t *testing.T) {
	var buf bytes.Buffer
	b := newTestBar(&buf, true)
	b.Done()
	if buf.Len() != 0 {
		t.Errorf("Done wrote %q with no prior output", buf.String())
	}
}

func TestDoneClosesTheLine(t *testing.T) {
	var buf bytes.Buffer
	b := newTestBar(&buf, true)
	b.Update(1, 100)
	b.Done()
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Error("the bar line was left open, so the next log message lands on top of it")
	}
}

func TestIsTerminalOnAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminal(w) {
		t.Error("a pipe was taken for a terminal")
	}
}
