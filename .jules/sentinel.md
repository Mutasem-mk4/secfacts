## 2024-05-18 - Insecure File Creation Permissions
**Vulnerability:** Files intended to store security exports or log outputs were created using `os.Create`, which inherently assigns `0666` permissions, making the output accessible to any user on the system (subject to umask).
**Learning:** `os.Create` should be avoided when creating sensitive files. Instead, `os.OpenFile` should be explicitly used along with file permissions (e.g., `0600`) to restrict read and write access to the file's owner exclusively.
**Prevention:** For files handling security findings, exports, or potentially sensitive logs, ensure explicit restrictive permissions (e.g., `0600`) are provided when generating the output.
