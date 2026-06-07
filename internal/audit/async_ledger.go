package audit

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"vaos-kernel/pkg/models"
)

// AsyncLedger implements Mode B: synchronous hash computation, asynchronous
// persistence. The intent fingerprint is computed before the JWT is issued
// (preserving cryptographic binding), but the chained ledger write is deferred
// to a background worker. The 60-second JWT TTL provides the consistency window.
type AsyncLedger struct {
	mu        sync.RWMutex
	entries   []models.AuditEntry
	lastHash  string
	logger    *log.Logger
	clock     func() time.Time
	lifecycle sync.RWMutex

	// Async components
	queue      chan models.AuditEntry
	bufferCap  int
	flushEvery time.Duration
	fallbacks  int64 // atomic counter: times queue backpressure was applied

	// Lifecycle
	closed int32 // atomic flag: 1 = closed
	done   chan struct{}
	wg     sync.WaitGroup
}

// AsyncConfig controls the async write-behind behavior.
type AsyncConfig struct {
	BufferSize    int           // Channel capacity (default 10000)
	FlushInterval time.Duration // Max time between flushes (default 100ms)
}

// DefaultAsyncConfig returns production defaults.
func DefaultAsyncConfig() AsyncConfig {
	return AsyncConfig{
		BufferSize:    10000,
		FlushInterval: 100 * time.Millisecond,
	}
}

// NewAsyncLedger creates a Mode B ledger with a background writer.
func NewAsyncLedger(writer io.Writer, cfg AsyncConfig) *AsyncLedger {
	if writer == nil {
		writer = io.Discard
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 10000
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 100 * time.Millisecond
	}

	al := &AsyncLedger{
		lastHash:   GenesisHash,
		logger:     log.New(writer, "", 0),
		clock:      func() time.Time { return time.Now().UTC() },
		queue:      make(chan models.AuditEntry, cfg.BufferSize),
		bufferCap:  cfg.BufferSize,
		flushEvery: cfg.FlushInterval,
		done:       make(chan struct{}),
	}

	// Start background writer
	al.wg.Add(1)
	go al.backgroundWriter()

	return al
}

// Record queues an audit entry for async persistence.
// The entry's timestamp is set synchronously (contemporaneous).
// If the buffer is full, it applies backpressure to preserve chain order.
func (al *AsyncLedger) Record(entry models.AuditEntry) (models.AuditEntry, error) {
	al.lifecycle.RLock()
	defer al.lifecycle.RUnlock()

	if atomic.LoadInt32(&al.closed) == 1 {
		return models.AuditEntry{}, errors.New("record audit entry: ledger is closed")
	}
	if entry.AgentID == "" {
		return models.AuditEntry{}, errMissingAgentID
	}
	if entry.Component == "" {
		return models.AuditEntry{}, errMissingComponent
	}
	if entry.Action == "" {
		return models.AuditEntry{}, errMissingAction
	}

	// Timestamp set synchronously — satisfies "contemporaneous"
	if entry.ID == "" {
		entry.ID = entry.Component + "-" + al.clock().Format("20060102150405.000000000")
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = al.clock()
	}

	// Compute and append the chain synchronously. Only persistence is async.
	al.mu.Lock()
	attestation, err := attestChained(entry, al.lastHash)
	if err != nil {
		al.mu.Unlock()
		return models.AuditEntry{}, err
	}
	entry.Attestation = attestation
	al.lastHash = attestation
	al.entries = append(al.entries, entry)

	// Enqueue while still holding the sequencing lock so persistence order
	// always matches hash-chain order.
	select {
	case al.queue <- entry:
		al.mu.Unlock()
	default:
		// A full queue must not let a later entry overtake this one.
		atomic.AddInt64(&al.fallbacks, 1)
		al.queue <- entry
		al.mu.Unlock()
	}
	return entry, nil
}

func (al *AsyncLedger) persist(entry models.AuditEntry) {
	payload, _ := json.Marshal(entry)
	al.logger.Print(string(payload))
}

// backgroundWriter drains the queue and persists already-chained entries.
func (al *AsyncLedger) backgroundWriter() {
	defer al.wg.Done()

	ticker := time.NewTicker(al.flushEvery)
	defer ticker.Stop()

	batch := make([]models.AuditEntry, 0, 1000)

	for {
		select {
		case entry := <-al.queue:
			batch = append(batch, entry)
			// Drain up to 1000 more without blocking
			for len(batch) < 1000 {
				select {
				case e := <-al.queue:
					batch = append(batch, e)
				default:
					goto flush
				}
			}
		flush:
			al.flushBatch(batch)
			batch = batch[:0]

		case <-ticker.C:
			// Periodic flush: drain queued entries and flush
			al.drainQueue(al.queue, &batch)
			if len(batch) > 0 {
				al.flushBatch(batch)
				batch = batch[:0]
			}

		case <-al.done:
			// Drain remaining entries
			close(al.queue)
			for e := range al.queue {
				batch = append(batch, e)
			}
			if len(batch) > 0 {
				al.flushBatch(batch)
			}
			return
		}
	}
}

// drainQueue pulls all available entries from the channel without blocking.
func (al *AsyncLedger) drainQueue(queue <-chan models.AuditEntry, batch *[]models.AuditEntry) {
	for {
		select {
		case e := <-queue:
			*batch = append(*batch, e)
		default:
			return
		}
	}
}

// flushBatch persists a batch of entries.
func (al *AsyncLedger) flushBatch(batch []models.AuditEntry) {
	for _, entry := range batch {
		al.persist(entry)
	}
}

// Entries returns a copy of all persisted ledger entries.
func (al *AsyncLedger) Entries() []models.AuditEntry {
	al.mu.RLock()
	defer al.mu.RUnlock()
	out := make([]models.AuditEntry, len(al.entries))
	copy(out, al.entries)
	return out
}

// Fallbacks returns the number of times queue backpressure was applied.
func (al *AsyncLedger) Fallbacks() int64 {
	return atomic.LoadInt64(&al.fallbacks)
}

// Pending returns the number of entries waiting in the queue.
func (al *AsyncLedger) Pending() int {
	return len(al.queue)
}

// Close drains the queue and stops the background writer.
func (al *AsyncLedger) Close() {
	al.lifecycle.Lock()
	atomic.StoreInt32(&al.closed, 1)
	close(al.done)
	al.lifecycle.Unlock()
	al.wg.Wait()
}

// VerifyChain walks all persisted entries and verifies hash chain integrity.
func (al *AsyncLedger) VerifyChain() int {
	al.mu.RLock()
	defer al.mu.RUnlock()

	prevHash := GenesisHash
	for i, entry := range al.entries {
		expected, err := attestChained(entry, prevHash)
		if err != nil || expected != entry.Attestation {
			return i
		}
		prevHash = entry.Attestation
	}
	return -1
}
