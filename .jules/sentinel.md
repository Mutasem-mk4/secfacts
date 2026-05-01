## 2024-05-24 - Default File Permissions with os.Create
**Vulnerability:** The application uses `os.Create` which creates files with 0666 permissions (before umask). This can lead to sensitive output files being readable or writable by other users on the system.
**Learning:** In Go, `os.Create` uses overly permissive default permissions (0666). In a security pipeline tool like Axon, output files could contain sensitive security findings.
**Prevention:** Use `os.OpenFile` with explicit, restrictive permissions like `0600` (read/write only by owner) when creating files that may contain sensitive data.
