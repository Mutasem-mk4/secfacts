## 2024-05-24 - Insecure Default File Creation Permissions (`os.Create`)
**Vulnerability:** Files created with `os.Create` default to `0666` permissions before umask, which can allow unauthorized read/write access to sensitive files (such as security reports) on multi-user systems.
**Learning:** `os.Create` is overly permissive for sensitive outputs in Go. Explicit permission control is required when writing sensitive data.
**Prevention:** Avoid `os.Create()`. Always use `os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)` (or `os.CreateTemp` for temp files) to enforce strict ownership and secure permissions.
