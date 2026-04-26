## 2024-05-15 - Memory overhead with large struct reallocations
**Learning:** Slices containing large structs by value (like evidence.RootCauseCluster containing evidence.Finding) cause significant memory overhead during slice reallocation.
**Action:** Always pre-allocate slices/maps to their exact required capacity (e.g. using pre-deduplicated map lengths) when storing large structs by value.
