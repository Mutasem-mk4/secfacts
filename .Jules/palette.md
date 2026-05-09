## 2024-05-09 - Fix tabwriter alignment with ANSI color codes
**Learning:** When formatting terminal output with Go's `text/tabwriter` and ANSI color codes, the `tabwriter.StripEscape` flag should be enabled unconditionally. The ANSI escape sequences themselves must be wrapped in `\xff` conditionally, only when outputting to a terminal via tabwriter, to prevent column misalignment without leaking invalid UTF-8 characters to standard io.Writers.
**Action:** Use `tabwriter.StripEscape` alongside `\xff` wrappers around ANSI code constants when printing formatted terminal tables.
