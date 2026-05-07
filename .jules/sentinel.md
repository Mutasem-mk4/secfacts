## 2024-05-07 - Insecure Default File Permissions
**Vulnerability:** Security report files were created using os.Create(), resulting in overly permissive default permissions (0666).
**Learning:** In Go, os.Create defaults to 0666 permissions. For sensitive outputs like security reports, this exposes them to unauthorized local access.
**Prevention:** Use os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) to explicitly set restricted (0600) permissions on sensitive files.
