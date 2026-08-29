package canopi

import (
	"bytes"
	"image"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
	"golang.org/x/image/font"
)

func TestPaginateSortsBeforeOverflowAndCountsOnlyOmittedAgents(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	agents := []protocol.Event{
		event("w1", "w1", protocol.StateWorking, now.Add(-time.Minute)),
		event("d1", "d1", protocol.StateDone, now.Add(-time.Minute)),
		event("q1", "q1", protocol.StateWaitingForUser, now.Add(-time.Minute)),
		event("w2", "w2", protocol.StateWorking, now.Add(-2*time.Minute)),
		event("w3", "w3", protocol.StateWorking, now.Add(-3*time.Minute)),
	}
	page, err := Paginate(agents, GridConfig{Columns: 2, Rows: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Agents) != 3 || page.Agents[0].State != protocol.StateWaitingForUser || page.Agents[1].State != protocol.StateDone {
		t.Fatalf("page agents = %#v", page.Agents)
	}
	if page.Omitted.Total != 2 || page.Omitted.Working != 2 || page.Omitted.Waiting != 0 || page.Omitted.Done != 0 {
		t.Fatalf("omitted = %+v", page.Omitted)
	}
}

func TestRenderIsDeterministicExactOneBit800x480PNG(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	agents := make([]protocol.Event, 0, 19)
	states := []protocol.State{protocol.StateWaitingForUser, protocol.StateWaitingForUser, protocol.StateWaitingForUser,
		protocol.StateDone, protocol.StateDone, protocol.StateDone, protocol.StateDone}
	for len(states) < 19 {
		states = append(states, protocol.StateWorking)
	}
	for i, state := range states {
		agents = append(agents, event(string(rune('a'+i)), "Agent / task", state, now.Add(-time.Duration(i)*time.Minute)))
	}
	config := RenderConfig{Width: 800, Height: 480, Grid: GridConfig{Columns: 2, Rows: 6}, RelativeTimeBucket: time.Minute, Title: "CANOPI"}
	first, err := Render(agents, config, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(agents, config, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("render changed inside one relative-time bucket")
	}
	decoded, err := png.Decode(bytes.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := decoded.Bounds(), image.Rect(0, 0, 800, 480); got != want {
		t.Fatalf("bounds = %v, want %v", got, want)
	}
	colors := map[uint32]struct{}{}
	for y := 0; y < 480; y++ {
		for x := 0; x < 800; x++ {
			r, _, _, _ := decoded.At(x, y).RGBA()
			colors[r] = struct{}{}
		}
	}
	if len(colors) != 2 {
		t.Fatalf("render has %d grayscale values, want exactly 2", len(colors))
	}
}

func TestRenderFitsCustomTitleBeforeTotals(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	agents := []protocol.Event{event("waiting", "Task", protocol.StateWaitingForUser, now)}
	config := DefaultRenderConfig()
	config.Title = "C"
	shortPNG, err := Render(agents, config, now)
	if err != nil {
		t.Fatal(err)
	}
	config.Title = strings.Repeat("CUSTOM DASHBOARD TITLE ", 8)
	longPNG, err := Render(agents, config, now)
	if err != nil {
		t.Fatal(err)
	}
	shortImage, err := png.Decode(bytes.NewReader(shortPNG))
	if err != nil {
		t.Fatal(err)
	}
	longImage, err := png.Decode(bytes.NewReader(longPNG))
	if err != nil {
		t.Fatal(err)
	}
	fonts, err := newRenderFonts()
	if err != nil {
		t.Fatal(err)
	}
	defer fonts.close()
	totals := "1 WAITING  •  0 DONE  •  0 WORKING"
	totalsLeft := 800 - 12 - font.MeasureString(fonts.state, totals).Ceil()
	for y := 0; y < 32; y++ {
		for x := totalsLeft; x < 800; x++ {
			if shortImage.At(x, y) != longImage.At(x, y) {
				t.Fatalf("custom title changed reserved totals area at (%d,%d)", x, y)
			}
		}
	}
}

func TestTileTitleUsesTheFullTopRow(t *testing.T) {
	bounds := image.Rect(5, 40, 398, 109)
	if got, want := titleAvailableWidth(bounds, 89), 299; got != want {
		t.Fatalf("titleAvailableWidth() = %d, want %d", got, want)
	}
}

func TestMachineLabelWidthReservesRelativeTimeAndGap(t *testing.T) {
	bounds := image.Rect(5, 40, 398, 109)
	if got, want := machineLabelAvailableWidth(bounds, 89, 42), 249; got != want {
		t.Fatalf("machineLabelAvailableWidth() = %d, want %d", got, want)
	}
}

func TestRenderRejectsUnusableGridShapes(t *testing.T) {
	for _, grid := range []GridConfig{{Columns: 3, Rows: 1}, {Columns: 1, Rows: 7}, {Columns: 48, Rows: 1}} {
		config := DefaultRenderConfig()
		config.Grid = grid
		if _, err := Render(nil, config, time.Now()); err == nil {
			t.Fatalf("Render() accepted unusable grid %dx%d", grid.Columns, grid.Rows)
		}
	}
}
