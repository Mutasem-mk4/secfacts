## 2024-05-17 - Fix overly permissive file permissions in output writers
**Vulnerability:** Security reports and output files were being created with Go's `os.Create` function, which uses `0666` permissions by default. This makes the created files readable and writable by other users on the system (if umask permits).
**Learning:** `os.Create` is overly permissive. When creating files containing sensitive security findings, it represents an information leak and tampering risk if created in shared environments (such as CI/CD containers or shared machines).
**Prevention:** Instead of using `os.Create`, use `os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)` to ensure files are explicitly created with `0600` permissions, which restrict read and write access to the file's owner.
