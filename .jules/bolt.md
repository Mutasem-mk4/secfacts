

## 2023-10-27 - Preventing Large Struct Memory Copies with Index-Based Slices
**Learning:** In Go, using value semantics in a `for _, item := range slice` loop with a large struct like `evidence.Finding` results in significant and redundant memory allocations. Each iteration deep copies the entire struct by value, driving up Garbage Collection (GC) pressure.
**Action:** When iterating over slices of large structs, always use index-based loop semantics combined with pointer references (e.g., `for i := range slice { ptr := &slice[i] ... }`) to avoid deep copies and prevent memory bottlenecks. Furthermore, avoid copying large struct values inside maps; instead, use maps to store indices mapped to struct values.
