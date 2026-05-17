

## 2023-10-27 - Preventing Large Struct Memory Copies with Index-Based Slices
**Learning:** In Go, using value semantics in a `for _, item := range slice` loop with a large struct like `evidence.Finding` results in significant and redundant memory allocations. Each iteration deep copies the entire struct by value, driving up Garbage Collection (GC) pressure.
**Action:** When iterating over slices of large structs, always use index-based loop semantics combined with pointer references (e.g., `for i := range slice { ptr := &slice[i] ... }`) to avoid deep copies and prevent memory bottlenecks. Furthermore, avoid copying large struct values inside maps; instead, use maps to store indices mapped to struct values.

## 2024-05-17 - GitHub Action local reference fix
**Learning:** In GitHub Action workflow definitions, referring to a local custom action (like `./axon`) fails if the action file (`action.yml`) sits at the repository's root but the workflow specifies a subdirectory name (e.g. `uses: ./axon`). This results in a "Can't find 'action.yml', 'action.yaml' or 'Dockerfile'" error.
**Action:** When using a custom local action defined at the root of the repository, always refer to it using `uses: ./` instead of `uses: ./<repo-name>`. Also, if the action expects a JSON format from Trivy, explicitly set the `format` to `json` and update the output filenames accordingly.
