1. Add `.Jules/palette.md` to record the critical UX/a11y learning about tabwriter and ANSI color code formatting.
2. Modify `internal/app/app.go` to safely use `\xff` wrapping for ANSI colors when printed through `tabwriter` to fix output alignment.
3. Modify `internal/core/services/pipeline.go` to also safely use `\xff` wrapping for ANSI colors when printed through `tabwriter` to fix output alignment.
4. Verify changes by executing local scan.
5. Execute pre commit instructions.
