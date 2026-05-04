## 2024-05-04 - Insecure File Permissions with os.Create
**Vulnerability:** Found `os.Create` being used to generate output files, which defaults to overly permissive 0666 permissions, potentially exposing sensitive security reports or findings to unauthorized local users.
**Learning:** In security tools, output files often contain sensitive information. `os.Create` uses default umask-modified permissions (typically resulting in 0644 or 0666) which is not secure enough.
**Prevention:** Avoid `os.Create` for sensitive files. Use `os.OpenFile` with explicit restrictve permissions like 0600 (`os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)`) to prevent local privilege escalation and unauthorized access.
