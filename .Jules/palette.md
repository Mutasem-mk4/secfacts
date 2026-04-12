## 2024-05-18 - Terminal Output Alignment with Emojis and ANSI Colors
**Learning:** Adding emojis and ANSI color codes to terminal outputs breaks alignment when using `text/tabwriter` because the escape sequences are counted as visible characters.
**Action:** Use `\xff` around ANSI escape codes and set the `tabwriter.StripEscape` flag to correctly instruct the tabwriter to ignore non-printable characters for alignment calculation. Emojis like 🚨 generally align correctly in tabwriter when the terminal supports them but require careful consideration of their real width.
