## 2024-05-18 - String concatenation in map keys for deduplication
**Learning:** Found string concatenation being used in a hot loop (during deduplication) to create map keys from struct fields, which causes unnecessary memory allocations and CPU overhead, despite the struct itself being comparable in Go.
**Action:** Use struct types as map keys directly in Go when all fields are comparable instead of creating composite string keys.
