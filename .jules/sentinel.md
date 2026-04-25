## 2025-03-05 - Restrictive File Permissions for Security Reports
**Vulnerability:** Overly permissive file permissions (0666) used when creating sensitive security reports using default `os.Create`.
**Learning:** Go's `os.Create` uses `0666` default permissions, which can allow local privilege escalation and unauthorized access when handling sensitive output files like security reports.
**Prevention:** Always use `os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)` with restrictive permissions (0600) instead of `os.Create` for sensitive data files.
