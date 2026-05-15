## 2024-05-15 - Insecure File Permissions in Logging
**Vulnerability:** The logging package created application log files and their parent directories with overly permissive permissions (`0o755` for directories, `0o644` for files).
**Learning:** Application logs often contain sensitive information. Creating log files or directories with world-readable permissions risks sensitive data disclosure to unauthorized local users.
**Prevention:** Always use restrictive permissions (`0o600` for files, `0o700` for directories) when creating sensitive output files and directories (like logs, credentials, or security reports).
