# Canopi design QA

Source visual truth: `docs/assets/canopi-selected-ui.png`

Implementation screenshot: `artifacts/canopi-implementation.png`

Final combined evidence: `artifacts/canopi-comparison-final.png`

Viewport: exact panel framebuffer, 800 x 480

State: simulator tick with 3 waiting, 4 done, 12 working, default 2 x 6 grid and corrected +8 overflow

## Normalization

The source is 1619 x 971 RGB (aspect ratio 1.667). It was downsampled to
`artifacts/canopi-reference-800x480.png` at the implementation's exact 800 x
480 panel dimensions. The implementation is a native 800 x 480, one-bit,
two-entry palette PNG. CSS size and device scale factor do not apply to this
server-side e-paper framebuffer. The comparison places the normalized source
and implementation side by side at 1:1 pixels without browser or device chrome.

## Findings

No actionable P0, P1, or P2 mismatch remains.

- Fonts and typography: the final implementation uses embedded Roboto Mono
  Regular/Bold with deterministic hinting and one-bit thresholding. Header,
  title, state, metadata and overflow hierarchy now tracks the mock closely.
  The harder pixel edges are an intentional physical-panel constraint, not a
  font fallback or antialiasing defect.
- Spacing and layout rhythm: header height, separator, two-column/six-row grid,
  tile gaps, icon column, three text baselines, right-aligned relative time and
  overflow subdivisions align with the normalized source. Titles use the full
  top row and no longer reserve bottom-metadata width.
- Colors and tokens: output contains exactly black and white. Waiting tiles are
  inverted; done tiles are solid outlined; working tiles are dashed outlined.
  There are no gradients, grey pixels, shadows or unsupported alpha.
- Image quality and asset fidelity: the renderer never displays or embeds the
  mock-up. Standard exclamation, check and play status marks are recreated as
  deterministic one-bit e-paper drawing primitives, as required by the source
  handoff. They remain crisp and optically centered at native resolution.
- Copy and content: CANOPI, totals, task labels, state labels, machine labels,
  relative times and omitted-tail counts match the selected direction. The
  third waiting and oldest done timestamps differ because the executable
  simulator keeps all cards inside the configured 30-minute non-terminal TTL
  and two-hour done retention; that is intentional dynamic data.
- Behavior and accessibility: semantic state is communicated by fill, border
  style, icon and text rather than color. Sorting and overflow are tested. The
  fixed physical display has no interactive, hover, focus or responsive states.
  HTTP ingestion, snapshot, render, bearer rejection and conditional 304 were
  exercised; browser console checks are not applicable to this non-browser UI.

## Comparison history

1. Pass 1 (`artifacts/canopi-comparison-pass1.png`) found P2 typography and
   content-order drift: the Go Mono face was too thin/serifed for the source,
   and simulator activity promoted the wrong working cards into visible slots.
   Fixes: pinned and embedded Roboto Mono under OFL, and made the simulator's
   selected visible ordering deterministic while preserving changing event
   timestamps.
2. Pass 2 (`artifacts/canopi-comparison-pass2.png`) found P2 density drift:
   title/state/meta weights were too light and text began too close to the icon
   column. Fixes: adjusted optical sizes, added deterministic bold overdraw,
   increased the icon-to-text gap, and introduced rounded solid tiles.
3. Final pass (`artifacts/canopi-comparison-final.png`) found the earlier P2s
   resolved. A last P2 title-truncation issue was fixed by allowing titles to
   use the whole top row. Post-fix evidence shows complete `indexino / XML
   parser` and `Spectre / permissions` labels, correct selected card ordering,
   and `0 WAITING / 0 DONE / 8 WORKING` overflow.

Focused crops were not needed: at 1600 x 480 the combined native-resolution
evidence keeps header type, all card text, border patterns, icons and overflow
labels readable in one view.

## Follow-up polish

- P3: dashed-tile corners are slightly squarer than the image-generation mock.
  The current form is more reliable as a one-bit repeated pattern and does not
  change hierarchy or readability.

## Implementation checklist

- [x] Exact 800 x 480 output
- [x] One-bit two-color palette
- [x] Selected state hierarchy and ordering
- [x] Configurable 2 x 6 default capacity and corrected overflow
- [x] Real embedded font files with redistribution license
- [x] Full title row without source-visible truncation
- [x] Native side-by-side comparison at matched dimensions

final result: passed
