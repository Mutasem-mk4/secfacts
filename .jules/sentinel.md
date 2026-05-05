## 2025-05-05 - Insecure File Permissions on Output Reports
**Vulnerability:** Found uses of `os.Create(path)` when generating output files (such as security scan reports). `os.Create` uses overly permissive default file permissions (`0666`), which could allow unauthorized local users to read or modify potentially sensitive security reports.
**Learning:** In Go, default file creation helpers like `os.Create` don't enforce strict security boundaries.
**Prevention:** Always use `os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)` to ensure files containing sensitive application data or security scan results are locked down to the owner upon creation.
