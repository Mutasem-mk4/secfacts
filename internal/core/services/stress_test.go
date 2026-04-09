package services

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/axon/axon/internal/core/domain"
)

func TestShardedNormalizer_Stress(t *testing.T) {
	// 1. Setup
	const (
		numWorkers     = 8
		totalFindings  = 100000
		uniqueFindings = 1000
	)

	norm := NewShardedNormalizer(numWorkers)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := make(chan domain.Evidence, 1000)
	out, errChan := norm.Process(ctx, in)

	// 2. Launch Publishers (Simulate concurrent streams)
	var wg sync.WaitGroup
	wg.Add(10) // 10 concurrent streams

	start := time.Now()
	go func() {
		for i := 0; i < 10; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < totalFindings/10; j++ {
					// Each stream sends some duplicates and some uniques
					uniqueID := j % uniqueFindings
					in <- domain.Evidence{
						ID:       fmt.Sprintf("raw-%d", uniqueID),
						Provider: "stress-test",
						Type:     domain.TypeSCA,
						Vulnerability: domain.Vulnerability{
							ID: fmt.Sprintf("CVE-2024-%04d", uniqueID),
						},
						Resource: domain.Resource{
							URI: fmt.Sprintf("pkg:npm/lib-%d@1.0.0", uniqueID),
						},
					}
				}
			}(i)
		}
		wg.Wait()
		close(in)
	}()

	// 3. Collect Results
	receivedCount := 0
	for range out {
		receivedCount++
	}

	duration := time.Since(start)

	// 4. Verify
	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("Normalizer error: %v", err)
		}
	default:
	}

	if receivedCount != uniqueFindings {
		t.Errorf("Deduplication failed: expected %d unique findings, got %d", uniqueFindings, receivedCount)
	}

	t.Logf("Processed %d findings (resulting in %d uniques) in %v", totalFindings, receivedCount, duration)
	t.Logf("Throughput: %.2f findings/sec", float64(totalFindings)/duration.Seconds())
}

func BenchmarkShardedNormalizer_Throughput(b *testing.B) {
	norm := NewShardedNormalizer(8)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in := make(chan domain.Evidence, 100)
		out, _ := norm.Process(ctx, in)

		go func() {
			for j := 0; j < 1000; j++ {
				in <- domain.Evidence{
					ID:            "id",
					Resource:      domain.Resource{URI: "path"},
					Vulnerability: domain.Vulnerability{ID: "V-1"},
				}
			}
			close(in)
		}()

		for range out {
		}
	}
}
