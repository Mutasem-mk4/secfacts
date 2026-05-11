## 2024-05-24 - [Fix Insecure File and Directory Permissions for Sensitive Outputs]
**Vulnerability:** Log files and reports containing sensitive security data were created using `os.Create` (0666 before umask), and logging directories were created with 0755, potentially allowing unauthorized read access to logs and reports.
**Learning:** `os.Create` defaults to `0666` which may be too permissive for sensitive files, exposing them to other users on the system if `umask` is not appropriately set. Directory permissions of `0755` allow any user on the system to list directory contents.
**Prevention:** Use `os.OpenFile` with `0600` for files containing sensitive data like security reports, logs, etc. Use `os.MkdirAll` with `0700` for logging or report directories.
