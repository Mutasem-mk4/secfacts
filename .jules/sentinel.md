## 2024-05-15 - Unsafe File Creation Permissions
**Vulnerability:** Creating output files with `os.Create` results in overly permissive `0666` defaults, exposing sensitive security reports.
**Learning:** `os.Create` should be avoided for any file containing sensitive data in Go.
**Prevention:** Use `os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)` to ensure files are only accessible by the owner.
