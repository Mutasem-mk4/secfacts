## 2025-03-09 - Avoid Value Semantic Loops with Large Structs
**Learning:** Iterating over slices of large structs (like `evidence.Finding` which contains many fields and nested pointers) using value semantics (`for _, item := range collection`) causes significant memory and CPU overhead due to repeated full struct copying on every loop iteration.
**Action:** Use index-based pointer semantics (`for i := range collection { item := &collection[i] }`) to operate on pointers to the slice elements directly when working with large or complex structs like those within Axon's evidence domain.
