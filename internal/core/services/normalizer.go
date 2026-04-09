package services

import (
	"context"
	"hash/fnv"
	"path/filepath"
	"strings"
	"sync"

	"github.com/axon/axon/internal/core/domain"
	"github.com/axon/axon/internal/core/ports"
)

// ShardedNormalizer implements the ports.Normalizer interface using a sharded actor model.
type ShardedNormalizer struct {
	workerCount int
}

// NewShardedNormalizer creates a new ShardedNormalizer with the specified worker count.
func NewShardedNormalizer(workerCount int) *ShardedNormalizer {
	if workerCount <= 0 {
		workerCount = 4
	}
	return &ShardedNormalizer{
		workerCount: workerCount,
	}
}

// Process handles the high-performance deduplication pipeline.
func (s *ShardedNormalizer) Process(ctx context.Context, in <-chan domain.Evidence) (<-chan domain.Evidence, <-chan error) {
	out := make(chan domain.Evidence)
	errChan := make(chan error, 1)

	// Initialize worker channels
	workerChans := make([]chan domain.Evidence, s.workerCount)
	for i := 0; i < s.workerCount; i++ {
		workerChans[i] = make(chan domain.Evidence, 100) // Buffered to prevent dispatcher stalls
	}

	var wg sync.WaitGroup
	wg.Add(s.workerCount)

	// Launch worker routines
	for i := 0; i < s.workerCount; i++ {
		go func(id int, ch <-chan domain.Evidence) {
			defer wg.Done()
			// Single-threaded state per worker - no locks required
			localStore := make(map[string]domain.Evidence)

			for ev := range ch {
				// 1. Path Cleaning & Resource Normalization
				ev.Resource.URI = s.normalizePath(ev.Resource.URI)

				// 2. ID Aliasing (e.g., mapping tool-specific secret IDs)
				ev.Vulnerability.ID = s.aliasID(ev.Vulnerability.ID, ev.Type)

				// 3. Semantic Fingerprinting
				fingerprint := s.computeFingerprint(ev)

				// 4. Deduplication Logic
				if _, exists := localStore[fingerprint]; !exists {
					localStore[fingerprint] = ev
				}
				// Potential future: Merge findings instead of just ignoring
			}

			// 5. Collection phase: Emit deduplicated results
			for _, deduped := range localStore {
				select {
				case out <- deduped:
				case <-ctx.Done():
					return
				}
			}
		}(i, workerChans[i])
	}

	// Dispatcher Routine
	go func() {
		defer func() {
			for _, ch := range workerChans {
				close(ch)
			}
			wg.Wait()
			close(out)
			close(errChan)
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-in:
				if !ok {
					return
				}

				// Compute routing hash based on raw identifiers before normalization
				// to ensure the same logical finding always hits the same worker.
				hash := s.computeRoutingHash(ev)
				workerIdx := hash % uint32(s.workerCount)

				select {
				case workerChans[workerIdx] <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return out, errChan
}

// normalizePath ensures consistent resource URIs.
func (s *ShardedNormalizer) normalizePath(path string) string {
	if path == "" {
		return path
	}
	// Remove common noise
	path = strings.TrimPrefix(path, "./")
	path = filepath.ToSlash(filepath.Clean(path))
	return path
}

// aliasID maps tool-specific IDs to canonical forms.
func (s *ShardedNormalizer) aliasID(id string, kind domain.FindingType) string {
	if kind == domain.TypeSecrets {
		// Canonicalize generic secret findings
		if strings.Contains(strings.ToLower(id), "gitleaks") || strings.Contains(strings.ToLower(id), "trivy-secret") {
			return "SEC-GENERIC-SECRET"
		}
	}
	return id
}

// computeFingerprint generates the final deduplication key.
func (s *ShardedNormalizer) computeFingerprint(ev domain.Evidence) string {
	h := fnv.New64a()
	// Vulnerability + Resource + Path is our semantic triplet
	_, _ = h.Write([]byte(ev.Vulnerability.ID))
	_, _ = h.Write([]byte(ev.Resource.URI))
	if ev.Location != nil {
		_, _ = h.Write([]byte(ev.Location.Path))
	}
	return string(h.Sum(nil))
}

// computeRoutingHash provides deterministic routing for the dispatcher.
func (s *ShardedNormalizer) computeRoutingHash(ev domain.Evidence) uint32 {
	h := fnv.New32a()
	// Route based on what makes a finding unique
	_, _ = h.Write([]byte(ev.Vulnerability.ID))
	_, _ = h.Write([]byte(ev.Resource.URI))
	return h.Sum32()
}

// Ensure interface compliance
var _ ports.Normalizer = (*ShardedNormalizer)(nil)
