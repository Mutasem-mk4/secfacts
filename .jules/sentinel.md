## 2024-05-17 - Insecure File Permissions in Output Files
**Vulnerability:** Found `os.Create` being used to generate security report files and `os.OpenFile` with `0o644` permissions for log files. This could allow unprivileged local users to read sensitive security findings and logs.
**Learning:** Default permissions in Go's `os.Create` are overly permissive (`0666` before umask). When handling sensitive data like security reports and logs, strict permissions must be explicitly enforced.
**Prevention:** Use `os.OpenFile` with specific flags (e.g., `os.O_CREATE|os.O_WRONLY|os.O_TRUNC`) and secure permissions (`0600` for files, `0700` for directories) when creating or writing files that may contain sensitive data.
