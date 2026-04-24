## 2026-04-24 - Insecure File Permissions for Security Reports

**Vulnerability:** Security reports and evidence output files were being created using Go's `os.Create` function, which defaults to 0666 file permissions.
**Learning:** `os.Create` in Go does not allow you to specify file permissions directly and defaults to very permissive settings that allow other users on the system to read and modify sensitive files. This could leak security vulnerability information in multi-tenant environments.
**Prevention:** Avoid `os.Create` when generating security reports or other sensitive output. Use `os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)` to ensure files are created with read/write permissions for the owner only.
