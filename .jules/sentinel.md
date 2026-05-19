## 2024-05-19 - Insecure file permissions for security reports
**Vulnerability:** Output files for security reports are created using os.Create with default 0666 permissions.
**Learning:** Sensitive files such as security reports should be created with restrictive permissions to prevent unauthorized access on multi-user systems.
**Prevention:** Use os.OpenFile with flags os.O_CREATE|os.O_WRONLY|os.O_TRUNC and permissions 0o600 for sensitive files.
