## 2025-05-18 - Optimize large struct loops

**Learning:** `evidence.Finding` is a massive struct. When using a `for _, item := range collection` loop on a slice of large structs, Go copies each struct into the `item` variable on every iteration. This introduces significant CPU overhead.
**Action:** Use index-based loop pointer semantics instead. Write `for i := range collection { item := &collection[i] }` to avoid expensive copies.
