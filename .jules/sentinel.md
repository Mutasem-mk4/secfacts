## 2025-02-14 - Fix overly permissive file permissions on output reports
**Vulnerability:** Go's `os.Create` function uses 0666 permissions by default, which can result in sensitive security reports being exposed or unauthorized local access.
**Learning:** For any code handling potentially sensitive security or log data outputs to files, we must be cautious of `os.Create` and default file mask limits, which lead to permissive file permissions.
**Prevention:** Instead of using `os.Create`, explicitly specify the restrictive file permission using `os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)`.
