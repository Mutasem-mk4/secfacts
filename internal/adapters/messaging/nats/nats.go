package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/axon/axon/internal/core/domain"
	"github.com/axon/axon/internal/core/ports"
	"github.com/nats-io/nats.go"
	"hash/fnv"
)

const (
	StreamName    = "axon_evidence"
	SubjectPrefix = "axon.evidence"
)

// NATSAdapter implements both Publisher and Subscriber for NATS JetStream.
type NATSAdapter struct {
	nc     *nats.Conn
	js     nats.JetStreamContext
	shards int
}

// NewNATSAdapter creates a new NATS adapter and ensures the JetStream is configured.
func NewNATSAdapter(url string, shards int) (*NATSAdapter, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("jetstream context: %w", err)
	}

	// Ensure the stream exists.
	_, err = js.AddStream(&nats.StreamConfig{
		Name:     StreamName,
		Subjects: []string{SubjectPrefix + ".>"},
		Storage:  nats.FileStorage,
	})
	if err != nil && err != nats.ErrStreamNameAlreadyInUse {
		return nil, fmt.Errorf("add stream: %w", err)
	}

	return &NATSAdapter{nc: nc, js: js, shards: shards}, nil
}

// Publish sends evidence to a sharded NATS subject.
func (a *NATSAdapter) Publish(ctx context.Context, ev domain.Evidence) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}

	shard := deterministicShard(ev.ID, a.shards)
	subject := fmt.Sprintf("%s.shard.%d", SubjectPrefix, shard)

	_, err = a.js.Publish(subject, data, nats.Context(ctx))
	if err != nil {
		return fmt.Errorf("js publish: %w", err)
	}

	return nil
}

// Subscribe listens to specific shards on NATS JetStream.
func (a *NATSAdapter) Subscribe(ctx context.Context, shards []int) (<-chan domain.Evidence, <-chan error) {
	evChan := make(chan domain.Evidence)
	errChan := make(chan error, 1)

	go func() {
		defer close(evChan)
		defer close(errChan)

		for _, shard := range shards {
			subject := fmt.Sprintf("%s.shard.%d", SubjectPrefix, shard)
			sub, err := a.js.PullSubscribe(subject, fmt.Sprintf("worker_shard_%d", shard), nats.PullMaxWaiting(128))
			if err != nil {
				errChan <- fmt.Errorf("pull subscribe shard %d: %w", shard, err)
				return
			}

			go func(s *nats.Subscription, sh int) {
				for {
					select {
					case <-ctx.Done():
						return
					default:
						msgs, err := s.Fetch(10, nats.Context(ctx))
						if err != nil {
							if err == context.DeadlineExceeded || err == nats.ErrTimeout {
								continue
							}
							errChan <- fmt.Errorf("fetch shard %d: %w", sh, err)
							return
						}

						for _, m := range msgs {
							var ev domain.Evidence
							if err := json.Unmarshal(m.Data, &ev); err != nil {
								// Log and skip bad data
								m.Ack()
								continue
							}
							// Assign manual Ack callback to avoid data loss during processing
							ev.Ack = func() error {
								return m.Ack()
							}
							evChan <- ev
						}
					}
				}
			}(sub, shard)
		}
		<-ctx.Done()
	}()

	return evChan, errChan
}

func deterministicShard(id string, totalShards int) int {
	h := fnv.New32a()
	h.Write([]byte(id))
	return int(h.Sum32() % uint32(totalShards))
}

var _ ports.Publisher = (*NATSAdapter)(nil)
var _ ports.Subscriber = (*NATSAdapter)(nil)
