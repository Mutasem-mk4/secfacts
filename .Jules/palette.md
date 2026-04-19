## 2024-04-19 - Initializing Palette Memory\n**Learning:** Memory initialized.\n**Action:** Keep learning.

## 2024-04-19 - Go TabWriter and ANSI Escape Alignment
**Learning:** In Go, passing ANSI escape color codes directly to `text/tabwriter` breaks tab-column alignment calculations because the hidden codes are treated as visible characters. The solution is to use `tabwriter.StripEscape` flag when constructing the writer and wrap the ANSI escape sequences with `\xff` characters.
**Action:** When working with `tabwriter` and CLI styling, always instantiate the writer with `tabwriter.StripEscape`, wrap all colors intended for the tabwriter in `\xff`, and keep separate variables for normal `io.Writer` colors to avoid literal `\xff` corruptions on standard outputs.
