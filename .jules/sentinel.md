## 2024-05-09 - Insecure Default File Permissions for Output and Logs

**Vulnerability:**
The application was creating output security reports and log files using `os.Create(path)` and `os.OpenFile(path, ..., 0o644)`, which results in files being readable by other users on the system. Log directories were created with `0o755`.

**Learning:**
Go's `os.Create` function defaults to `0666` permissions (before umask). Creating sensitive output files or directories in this repository (such as security reports or application logs) requires explicit restrictive permissions to prevent local privilege escalation and unauthorized access.

**Prevention:**
Always use `os.OpenFile` with `0600` permissions for sensitive files instead of `os.Create`. Use `0700` permissions for sensitive directories via `os.MkdirAll`. Go's `os.CreateTemp` safely uses `0600` by default and is preferred when generating temporary files.
