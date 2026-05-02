## 2025-05-15 - [Avoid value copying of large structs in loops]
**Learning:** Iterating over slices of large structs (like `evidence.Finding`) using value semantics (`for _, item := range collection`) causes significant CPU overhead due to repeated memory copies during each iteration.
**Action:** Use index-based pointer semantics (`for i := range collection { item := &collection[i] }`) to avoid implicit memory copying and improve iteration performance, especially in hot paths like correlation pipelines.
