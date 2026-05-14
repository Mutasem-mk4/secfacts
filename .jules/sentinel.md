## 2025-02-28 - Restrictive File Permissions for Sensitive Data
**Vulnerability:** Application logs and output security reports were being created with permissive permissions (0644/0755), potentially exposing sensitive findings, infrastructure details, and system states to unauthorized local users.
**Learning:** Default permissions for file creation operations like `os.Create` are overly permissive for sensitive data. Explicitly specifying secure permissions like `0600` for files and `0700` for directories is crucial for preventing local privilege escalation and data leakage.
**Prevention:** Always use `os.OpenFile` with explicit permissions (`0o600`) for sensitive files and `os.MkdirAll` with `0o700` for their parent directories rather than relying on default `os.Create` behaviors.
