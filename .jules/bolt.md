## 2026-04-09 - Avoid copying large structs into maps
**Learning:** In Go, assigning large structs (like `evidence.Finding`) to maps (e.g., `map[Key]Struct`) copies the entire struct by value, causing significant CPU and memory overhead during iteration.
**Action:** Use `map[Key]int` to store slice indices instead of values, and access the struct via the slice using the index (`collection[index]`).
