package canopi

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"strings"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

// GridConfig controls the fixed panel's agent-tile capacity.
type GridConfig struct {
	Columns int
	Rows    int
}

// RenderConfig controls deterministic 800x480 panel rendering.
type RenderConfig struct {
	Width              int
	Height             int
	Grid               GridConfig
	RelativeTimeBucket time.Duration
	Title              string
}

// DefaultRenderConfig returns the selected concept's two-by-six layout.
func DefaultRenderConfig() RenderConfig {
	return RenderConfig{
		Width: 800, Height: 480,
		Grid:               GridConfig{Columns: 2, Rows: 6},
		RelativeTimeBucket: time.Minute,
		Title:              "CANOPI",
	}
}

func (c RenderConfig) validate() error {
	if c.Width != 800 || c.Height != 480 {
		return errors.New("canopi panel rendering must be exactly 800x480")
	}
	if c.Grid.Columns <= 0 || c.Grid.Rows <= 0 || c.Grid.Columns*c.Grid.Rows > 48 {
		return errors.New("grid capacity must be between 1 and 48")
	}
	if c.RelativeTimeBucket <= 0 {
		return errors.New("relative time bucket must be positive")
	}
	if strings.TrimSpace(c.Title) == "" {
		return errors.New("render title is required")
	}
	return nil
}

// OverflowCounts reports the omitted tail by lifecycle state.
type OverflowCounts struct {
	Total   int
	Waiting int
	Done    int
	Working int
}

// Page contains visible agents plus the overflow summary tile counts.
type Page struct {
	Agents  []protocol.Event
	Omitted OverflowCounts
}

// Paginate sorts agents and reserves the final slot for overflow when needed.
func Paginate(agents []protocol.Event, grid GridConfig) (Page, error) {
	capacity := grid.Columns * grid.Rows
	if grid.Columns <= 0 || grid.Rows <= 0 || capacity > 48 {
		return Page{}, errors.New("grid capacity must be between 1 and 48")
	}
	sorted := append([]protocol.Event(nil), agents...)
	SortEvents(sorted)
	if len(sorted) <= capacity {
		return Page{Agents: sorted}, nil
	}
	page := Page{Agents: append([]protocol.Event(nil), sorted[:capacity-1]...)}
	for _, event := range sorted[capacity-1:] {
		page.Omitted.Total++
		switch event.State {
		case protocol.StateWaitingForUser:
			page.Omitted.Waiting++
		case protocol.StateDone:
			page.Omitted.Done++
		case protocol.StateWorking:
			page.Omitted.Working++
		}
	}
	return page, nil
}

type renderFonts struct {
	header font.Face
	title  font.Face
	state  font.Face
	meta   font.Face
	over   font.Face
}

// Roboto Mono is bundled under the SIL Open Font License in assets/OFL.txt.
// The source revision and asset hashes are recorded in docs/canopi.md.
//
//go:embed assets/RobotoMono-Regular.ttf
var robotoMonoRegular []byte

//go:embed assets/RobotoMono-Bold.ttf
var robotoMonoBold []byte

func (f renderFonts) close() {
	for _, face := range []font.Face{f.header, f.title, f.state, f.meta, f.over} {
		if closer, ok := face.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
}

func newRenderFonts() (renderFonts, error) {
	regular, err := opentype.Parse(robotoMonoRegular)
	if err != nil {
		return renderFonts{}, err
	}
	bold, err := opentype.Parse(robotoMonoBold)
	if err != nil {
		return renderFonts{}, err
	}
	face := func(parsed *opentype.Font, size float64) (font.Face, error) {
		return opentype.NewFace(parsed, &opentype.FaceOptions{Size: size, DPI: 72, Hinting: font.HintingFull})
	}
	header, err := face(bold, 25)
	if err != nil {
		return renderFonts{}, err
	}
	title, err := face(bold, 20.5)
	if err != nil {
		return renderFonts{}, err
	}
	state, err := face(bold, 16)
	if err != nil {
		return renderFonts{}, err
	}
	meta, err := face(regular, 14)
	if err != nil {
		return renderFonts{}, err
	}
	over, err := face(bold, 13)
	if err != nil {
		return renderFonts{}, err
	}
	return renderFonts{header: header, title: title, state: state, meta: meta, over: over}, nil
}

var (
	black = color.RGBA{A: 0xff}
	white = color.RGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
)

// Render produces a deterministic, one-bit-safe PNG at exactly 800x480.
func Render(agents []protocol.Event, config RenderConfig, now time.Time) ([]byte, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	page, err := Paginate(agents, config.Grid)
	if err != nil {
		return nil, err
	}
	fonts, err := newRenderFonts()
	if err != nil {
		return nil, fmt.Errorf("load renderer fonts: %w", err)
	}
	defer fonts.close()
	canvas := image.NewRGBA(image.Rect(0, 0, config.Width, config.Height))
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{C: white}, image.Point{}, draw.Src)
	bucketedNow := now.Truncate(config.RelativeTimeBucket)
	drawHeader(canvas, fonts, config.Title, agents)
	drawGrid(canvas, fonts, config, page, bucketedNow)
	oneBit := threshold(canvas)
	var output bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.BestCompression}
	if err := encoder.Encode(&output, oneBit); err != nil {
		return nil, fmt.Errorf("encode one-bit PNG: %w", err)
	}
	return output.Bytes(), nil
}

func drawHeader(canvas *image.RGBA, fonts renderFonts, title string, agents []protocol.Event) {
	drawBoldText(canvas, fonts.header, 12, 28, black, strings.ToUpper(title))
	var totals Totals
	for _, event := range agents {
		switch event.State {
		case protocol.StateWaitingForUser:
			totals.Waiting++
		case protocol.StateDone:
			totals.Done++
		case protocol.StateWorking:
			totals.Working++
		}
	}
	text := fmt.Sprintf("%d WAITING  •  %d DONE  •  %d WORKING", totals.Waiting, totals.Done, totals.Working)
	width := font.MeasureString(fonts.state, text).Ceil()
	drawBoldText(canvas, fonts.state, canvas.Bounds().Dx()-12-width, 26, black, text)
	fillRect(canvas, image.Rect(2, 32, canvas.Bounds().Dx()-2, 36), black)
}

func drawGrid(canvas *image.RGBA, fonts renderFonts, config RenderConfig, page Page, now time.Time) {
	const margin = 5
	const gap = 4
	top := 40
	availableWidth := config.Width - 2*margin - (config.Grid.Columns-1)*gap
	availableHeight := config.Height - top - margin - (config.Grid.Rows-1)*gap
	capacity := config.Grid.Columns * config.Grid.Rows
	for slot := 0; slot < capacity; slot++ {
		column := slot % config.Grid.Columns
		row := slot / config.Grid.Columns
		x0 := margin + column*availableWidth/config.Grid.Columns + column*gap
		x1 := margin + (column+1)*availableWidth/config.Grid.Columns + column*gap
		y0 := top + row*availableHeight/config.Grid.Rows + row*gap
		y1 := top + (row+1)*availableHeight/config.Grid.Rows + row*gap
		bounds := image.Rect(x0, y0, x1, y1)
		if slot < len(page.Agents) {
			drawAgentTile(canvas, fonts, bounds, page.Agents[slot], now)
		} else if page.Omitted.Total > 0 && slot == capacity-1 {
			drawOverflowTile(canvas, fonts, bounds, page.Omitted)
		}
	}
}

func drawAgentTile(canvas *image.RGBA, fonts renderFonts, bounds image.Rectangle, event protocol.Event, now time.Time) {
	foreground, background := black, white
	switch event.State {
	case protocol.StateWaitingForUser:
		foreground, background = white, black
		fillRoundedRect(canvas, bounds, 5, background)
	case protocol.StateWorking:
		drawDashedRect(canvas, bounds, 3, 10, 5, black)
	default:
		drawRoundedOutline(canvas, bounds, 5, 3, black, white)
	}
	iconSize := minInt(bounds.Dy()-14, 48)
	iconX := bounds.Min.X + 14 + iconSize/2
	iconY := bounds.Min.Y + bounds.Dy()/2
	drawStateIcon(canvas, iconX, iconY, iconSize/2, event.State, foreground, background)
	textX := iconX + iconSize/2 + 22
	timeText := relativeTime(now, event.ActivityAt)
	timeWidth := font.MeasureString(fonts.meta, timeText).Ceil()
	maxTitleWidth := titleAvailableWidth(bounds, textX)
	title := fitText(fonts.title, event.Task.Title, maxTitleWidth)
	drawBoldText(canvas, fonts.title, textX, bounds.Min.Y+24, foreground, title)
	stateText := strings.ToUpper(strings.ReplaceAll(string(event.State), "_", " "))
	drawBoldText(canvas, fonts.state, textX, bounds.Min.Y+44, foreground, stateText)
	drawText(canvas, fonts.meta, textX, bounds.Max.Y-7, foreground, fitText(fonts.meta, event.Machine.Label, maxTitleWidth))
	drawText(canvas, fonts.meta, bounds.Max.X-10-timeWidth, bounds.Max.Y-7, foreground, timeText)
}

func titleAvailableWidth(bounds image.Rectangle, textX int) int {
	return bounds.Max.X - 10 - textX
}

func drawOverflowTile(canvas *image.RGBA, fonts renderFonts, bounds image.Rectangle, counts OverflowCounts) {
	drawRoundedOutline(canvas, bounds, 5, 3, black, white)
	drawBoldText(canvas, fonts.title, bounds.Min.X+15, bounds.Min.Y+25, black, fmt.Sprintf("+%d MORE", counts.Total))
	labels := []struct {
		count int
		state protocol.State
		label string
	}{{counts.Waiting, protocol.StateWaitingForUser, "WAITING"}, {counts.Done, protocol.StateDone, "DONE"}, {counts.Working, protocol.StateWorking, "WORKING"}}
	sectionWidth := bounds.Dx() / len(labels)
	for index, label := range labels {
		x := bounds.Min.X + index*sectionWidth
		if index > 0 {
			fillRect(canvas, image.Rect(x, bounds.Min.Y+31, x+2, bounds.Max.Y-4), black)
		}
		iconRadius := minInt(13, bounds.Dy()/5)
		drawStateIcon(canvas, x+18, bounds.Max.Y-18, iconRadius, label.state, black, white)
		drawBoldText(canvas, fonts.over, x+37, bounds.Max.Y-12, black, fmt.Sprintf("%d %s", label.count, label.label))
	}
}

func drawStateIcon(canvas *image.RGBA, cx, cy, radius int, state protocol.State, foreground, background color.RGBA) {
	if radius < 4 {
		return
	}
	switch state {
	case protocol.StateWaitingForUser:
		fillCircle(canvas, cx, cy, radius, foreground)
		drawThickLine(canvas, cx, cy-radius/2, cx, cy+radius/5, maxInt(2, radius/6), background)
		fillCircle(canvas, cx, cy+radius/2, maxInt(1, radius/9), background)
	case protocol.StateDone:
		drawCircle(canvas, cx, cy, radius, maxInt(2, radius/8), foreground)
		drawThickLine(canvas, cx-radius/2, cy, cx-radius/7, cy+radius/3, maxInt(2, radius/7), foreground)
		drawThickLine(canvas, cx-radius/7, cy+radius/3, cx+radius/2, cy-radius/3, maxInt(2, radius/7), foreground)
	case protocol.StateWorking:
		fillCircle(canvas, cx, cy, radius, foreground)
		fillTriangle(canvas, image.Pt(cx-radius/4, cy-radius/2), image.Pt(cx-radius/4, cy+radius/2), image.Pt(cx+radius/2, cy), background)
	}
}

func relativeTime(now, activity time.Time) string {
	age := now.Sub(activity)
	if age < time.Minute {
		return "now"
	}
	if age < time.Hour {
		return fmt.Sprintf("%dm ago", int(age/time.Minute))
	}
	if age < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(age/time.Hour))
	}
	return fmt.Sprintf("%dd ago", int(age/(24*time.Hour)))
}

func fitText(face font.Face, text string, maxWidth int) string {
	if maxWidth <= 0 || font.MeasureString(face, text).Ceil() <= maxWidth {
		return text
	}
	runes := []rune(text)
	for len(runes) > 1 {
		runes = runes[:len(runes)-1]
		candidate := string(runes) + "…"
		if font.MeasureString(face, candidate).Ceil() <= maxWidth {
			return candidate
		}
	}
	return "…"
}

func drawText(canvas *image.RGBA, face font.Face, x, baseline int, colour color.RGBA, text string) {
	drawer := font.Drawer{Dst: canvas, Src: &image.Uniform{C: colour}, Face: face, Dot: fixed.P(x, baseline)}
	drawer.DrawString(text)
}

func drawBoldText(canvas *image.RGBA, face font.Face, x, baseline int, colour color.RGBA, text string) {
	drawText(canvas, face, x, baseline, colour, text)
	drawText(canvas, face, x+1, baseline, colour, text)
}

func fillRect(canvas *image.RGBA, bounds image.Rectangle, colour color.RGBA) {
	draw.Draw(canvas, bounds.Intersect(canvas.Bounds()), &image.Uniform{C: colour}, image.Point{}, draw.Src)
}

func fillRoundedRect(canvas *image.RGBA, bounds image.Rectangle, radius int, colour color.RGBA) {
	if radius <= 0 || bounds.Dx() <= 2*radius || bounds.Dy() <= 2*radius {
		fillRect(canvas, bounds, colour)
		return
	}
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		inset := 0
		if y < bounds.Min.Y+radius {
			dy := bounds.Min.Y + radius - y
			inset = radius - int(math.Sqrt(float64(radius*radius-dy*dy)))
		} else if y >= bounds.Max.Y-radius {
			dy := y - (bounds.Max.Y - radius - 1)
			inset = radius - int(math.Sqrt(float64(radius*radius-dy*dy)))
		}
		fillRect(canvas, image.Rect(bounds.Min.X+inset, y, bounds.Max.X-inset, y+1), colour)
	}
}

func drawRoundedOutline(canvas *image.RGBA, bounds image.Rectangle, radius, thickness int, foreground, background color.RGBA) {
	fillRoundedRect(canvas, bounds, radius, foreground)
	inner := bounds.Inset(thickness)
	fillRoundedRect(canvas, inner, maxInt(0, radius-thickness), background)
}

func drawDashedRect(canvas *image.RGBA, bounds image.Rectangle, thickness, dash, spacing int, colour color.RGBA) {
	for x := bounds.Min.X; x < bounds.Max.X; x += dash + spacing {
		fillRect(canvas, image.Rect(x, bounds.Min.Y, minInt(x+dash, bounds.Max.X), bounds.Min.Y+thickness), colour)
		fillRect(canvas, image.Rect(x, bounds.Max.Y-thickness, minInt(x+dash, bounds.Max.X), bounds.Max.Y), colour)
	}
	for y := bounds.Min.Y; y < bounds.Max.Y; y += dash + spacing {
		fillRect(canvas, image.Rect(bounds.Min.X, y, bounds.Min.X+thickness, minInt(y+dash, bounds.Max.Y)), colour)
		fillRect(canvas, image.Rect(bounds.Max.X-thickness, y, bounds.Max.X, minInt(y+dash, bounds.Max.Y)), colour)
	}
}

func fillCircle(canvas *image.RGBA, cx, cy, radius int, colour color.RGBA) {
	for y := -radius; y <= radius; y++ {
		half := int(math.Sqrt(float64(radius*radius - y*y)))
		fillRect(canvas, image.Rect(cx-half, cy+y, cx+half+1, cy+y+1), colour)
	}
}

func drawCircle(canvas *image.RGBA, cx, cy, radius, thickness int, colour color.RGBA) {
	outer := radius * radius
	innerRadius := maxInt(0, radius-thickness)
	inner := innerRadius * innerRadius
	for y := -radius; y <= radius; y++ {
		for x := -radius; x <= radius; x++ {
			distance := x*x + y*y
			if distance <= outer && distance >= inner {
				canvas.Set(cx+x, cy+y, colour)
			}
		}
	}
}

func drawThickLine(canvas *image.RGBA, x0, y0, x1, y1, thickness int, colour color.RGBA) {
	dx, dy := x1-x0, y1-y0
	steps := maxInt(absInt(dx), absInt(dy))
	if steps == 0 {
		fillCircle(canvas, x0, y0, thickness/2, colour)
		return
	}
	for step := 0; step <= steps; step++ {
		x := x0 + dx*step/steps
		y := y0 + dy*step/steps
		fillCircle(canvas, x, y, maxInt(1, thickness/2), colour)
	}
}

func fillTriangle(canvas *image.RGBA, a, b, c image.Point, colour color.RGBA) {
	minX, maxX := minInt(a.X, minInt(b.X, c.X)), maxInt(a.X, maxInt(b.X, c.X))
	minY, maxY := minInt(a.Y, minInt(b.Y, c.Y)), maxInt(a.Y, maxInt(b.Y, c.Y))
	sign := func(p1, p2, p3 image.Point) int {
		return (p1.X-p3.X)*(p2.Y-p3.Y) - (p2.X-p3.X)*(p1.Y-p3.Y)
	}
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			point := image.Pt(x, y)
			d1, d2, d3 := sign(point, a, b), sign(point, b, c), sign(point, c, a)
			if (d1 < 0 || d2 < 0 || d3 < 0) && (d1 > 0 || d2 > 0 || d3 > 0) {
				continue
			}
			canvas.Set(x, y, colour)
		}
	}
}

func threshold(source *image.RGBA) *image.Paletted {
	palette := color.Palette{white, black}
	target := image.NewPaletted(source.Bounds(), palette)
	for y := source.Bounds().Min.Y; y < source.Bounds().Max.Y; y++ {
		for x := source.Bounds().Min.X; x < source.Bounds().Max.X; x++ {
			r, g, b, _ := source.At(x, y).RGBA()
			if (r+g+b)/3 < 0x8000 {
				target.SetColorIndex(x, y, 1)
			}
		}
	}
	return target
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
