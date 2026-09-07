// Package progress renders download progress on a terminal.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const barWidth = 30

// Bar draws a one-line progress bar on w, redrawn in place. When w is not a
// terminal — a CI log, a pipe, a redirect — it prints one line per decile
// instead, because carriage returns in a log file produce an unreadable single
// line kilometres wide.
type Bar struct {
	w         io.Writer
	tty       bool
	start     time.Time
	lastPct   int
	anyOutput bool
}

// NewBar writes to stderr, leaving stdout free for piping the actual output.
func NewBar() *Bar {
	return &Bar{w: os.Stderr, tty: isTerminal(os.Stderr), start: time.Now(), lastPct: -1}
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// Update reports written of total bytes. total may be 0 when the server did not
// announce a length, in which case no percentage or ETA is shown.
func (b *Bar) Update(written, total int64) {
	elapsed := time.Since(b.start)
	rate := float64(written) / max(elapsed.Seconds(), 0.001)

	if total <= 0 {
		b.line(fmt.Sprintf("%s downloaded, %s/s", humanBytes(written), humanBytes(int64(rate))))
		return
	}

	pct := int(float64(written) * 100 / float64(total))
	if !b.tty {
		// One line per decile: enough to see it is alive, few enough to read.
		if pct/10 == b.lastPct/10 && pct < 100 {
			return
		}
		b.lastPct = pct
		fmt.Fprintf(b.w, "%3d%% %s / %s at %s/s\n", pct, humanBytes(written), humanBytes(total), humanBytes(int64(rate)))
		b.anyOutput = true
		return
	}

	filled := pct * barWidth / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	b.line(fmt.Sprintf("[%s] %3d%%  %s / %s  %s/s  ETA %s",
		bar, pct, humanBytes(written), humanBytes(total), humanBytes(int64(rate)), eta(written, total, rate)))
}

func (b *Bar) line(s string) {
	if !b.tty {
		return
	}
	fmt.Fprintf(b.w, "\r\033[K%s", s)
	b.anyOutput = true
}

// Done closes the line so the next log message starts on its own row.
func (b *Bar) Done() {
	if b.tty && b.anyOutput {
		fmt.Fprintln(b.w)
	}
}

func eta(written, total int64, rate float64) string {
	if rate <= 0 || written >= total {
		return "--:--"
	}
	left := time.Duration(float64(total-written)/rate) * time.Second
	if h := int(left.Hours()); h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, int(left.Minutes())%60, int(left.Seconds())%60)
	}
	return fmt.Sprintf("%02d:%02d", int(left.Minutes()), int(left.Seconds())%60)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
