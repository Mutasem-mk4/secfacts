
## 2024-05-18 - [Insecure Default Log File Permissions]
**Vulnerability:** The logger in `internal/bootstrap/logging.go` was creating log directories and files with overly permissive settings (0755 for directory, 0644 for file). Log files often contain sensitive debugging information or paths that can be accessed by any user on the system.
**Learning:** Default permissions in Go (`0755`, `0644`) are often overly permissive for security tools where logs might expose sensitive metadata, finding details, or execution context. The application shouldn't leak sensitive data through logs.
**Prevention:** Always restrict log file and directory creation permissions explicitly to the owner (`0700` for directories, `0600` for files) using `os.MkdirAll` and `os.OpenFile` unless broader access is explicitly required and verified safe.
