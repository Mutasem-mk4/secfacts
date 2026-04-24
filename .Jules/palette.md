## 2025-02-20 - [Terminal UI Alignment with Go Tabwriter]
**Learning:** When adding ANSI color codes or emojis to terminal output formatted with Go's `text/tabwriter`, the column alignment breaks because `tabwriter` counts the invisible escape sequences as visible characters.
**Action:** To fix this, always initialize `tabwriter` with the `tabwriter.StripEscape` flag and wrap all ANSI color sequences in `\xff` bytes. This instructs `tabwriter` to ignore the wrapped characters when calculating column widths, ensuring perfect alignment while still rendering colors and emojis correctly.
