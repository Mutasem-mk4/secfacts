## 2025-05-18 - [Optimization of computeFingerprint]
**Learning:** `localStore := make(map[string]domain.Evidence)` in `internal/core/services/normalizer.go` uses string keys to track deduplications. `string` keys created by converting bytes allocate heavily on the heap.
**Action:** Changed the map to `map[uint64]domain.Evidence` and use `h.Sum64()` instead of `string(h.Sum(nil))` to avoid heap allocations and string casting. The Go compiler optimizes `[]byte(string)` conversion in `h.Write([]byte(string))` so no need to avoid that.
