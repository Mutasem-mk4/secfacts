# Contributing to axon

First off, thank you for considering contributing to `axon`! It's people like you who make this tool a gold standard for the security community.

## 🛠️ How to Add a New Parser

`axon` is built on a modular **Interface-based Provider** pattern. Adding a new tool (e.g., Snyk, SonarQube, ZAP) is straightforward.

1.  **Define the Adapter:** Create a new file in `internal/adapters/ingestion/<tool_name>.go`.
2.  **Implement the Interface:** Your struct must satisfy the `ports.Parser` interface:
    ```go
    type Parser interface {
        Name() string
        Parse(ctx context.Context, r io.Reader) (<-chan domain.Evidence, <-chan error)
    }
    ```
3.  **Use Streaming:** Always use `json.NewDecoder` or equivalent streaming decoders. **Never** `json.Unmarshal` an entire file into memory.
4.  **Register Your Parser:** Add your parser to the registry in `internal/cmd/scan.go`'s `init()` function:
    ```go
    ingestion.Register(ingestion.NewMyNewToolParser())
    ```

## 🐛 Reporting Bugs

Please use our [Issue Template](.github/ISSUE_TEMPLATE/bug_report.md) and include:
- A minimal reproduction SARIF/JSON file.
- The `axon` version (`axon --version`).
- Observed vs. Expected output.

## 💡 Feature Requests

We love visionary ideas! Open an issue using the [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.md).

## ⚖️ Code of Conduct

We are committed to a welcoming and inclusive environment. Please read our [Code of Conduct](CODE_OF_CONDUCT.md).

---
*Engineering-First. Community-Driven. Security-Focused.*

