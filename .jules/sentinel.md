## 2024-05-24 - File Creation Permissions
**Vulnerability:** Use of `os.Create` creates files with excessively permissive permissions (0666 before umask).
**Learning:** For a security tooling project, creating sensitive outputs like normalized security reports with loose permissions can allow unauthorized local access or modification by other users on the system.
**Prevention:** Use `os.OpenFile` with explicit strict permissions like `0600` when creating sensitive files.
