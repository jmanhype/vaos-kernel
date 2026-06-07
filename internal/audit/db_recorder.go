package audit

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/lib/pq"
	"vaos-kernel/pkg/models"
)

// DBLedger is Mode A with Postgres persistence: hash chain + synchronous fsync write.
type DBLedger struct {
	mu         sync.Mutex
	entries    []models.AuditEntry
	anchorHash string
	lastHash   string
	maxEntries int
	db         *sql.DB
	logger     *log.Logger
	clock      func() time.Time
	stmt       *sql.Stmt
}

// NewDBLedger creates a Mode A ledger backed by Postgres with fsync.
func NewDBLedger(dbDSN string, logWriter io.Writer) (*DBLedger, error) {
	db, err := sql.Open("postgres", dbDSN)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(20)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureAuditSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	entries, anchorHash, lastHash, err := loadAuditEntries(db, defaultMaxEntries)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	stmt, err := db.Prepare(`INSERT INTO audit_ledger
		(id, timestamp, timestamp_ns, agent_id, intent_fingerprint, action, component, status, details, attestation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	if logWriter == nil {
		logWriter = io.Discard
	}

	return &DBLedger{
		entries:    entries,
		anchorHash: anchorHash,
		lastHash:   lastHash,
		maxEntries: defaultMaxEntries,
		db:         db,
		logger:     log.New(logWriter, "", 0),
		clock:      func() time.Time { return time.Now().UTC() },
		stmt:       stmt,
	}, nil
}

func (dl *DBLedger) Record(entry models.AuditEntry) (models.AuditEntry, error) {
	if entry.AgentID == "" {
		return models.AuditEntry{}, errMissingAgentID
	}
	if entry.Component == "" {
		return models.AuditEntry{}, errMissingComponent
	}
	if entry.Action == "" {
		return models.AuditEntry{}, errMissingAction
	}

	if entry.ID == "" {
		entry.ID = entry.Component + "-" + dl.clock().Format("20060102150405.000000000")
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = dl.clock()
	}

	dl.mu.Lock()
	attestation, err := attestChained(entry, dl.lastHash)
	if err != nil {
		dl.mu.Unlock()
		return models.AuditEntry{}, err
	}
	entry.Attestation = attestation

	// Synchronous DB write with fsync (Postgres WAL)
	detailsJSON, _ := json.Marshal(entry.Details)
	_, err = dl.stmt.Exec(
		entry.ID, entry.Timestamp, entry.Timestamp.UnixNano(), entry.AgentID, entry.IntentFingerprint,
		entry.Action, entry.Component, entry.Status, detailsJSON, entry.Attestation,
	)
	if err != nil {
		dl.mu.Unlock()
		return models.AuditEntry{}, err
	}

	dl.lastHash = attestation
	dl.entries = append(dl.entries, entry)
	if dl.maxEntries > 0 && len(dl.entries) > dl.maxEntries {
		half := len(dl.entries) / 2
		dl.anchorHash = dl.entries[half-1].Attestation
		dl.entries = dl.entries[half:]
	}
	dl.mu.Unlock()

	return entry, nil
}

func (dl *DBLedger) Entries() []models.AuditEntry {
	entries, _ := dl.Snapshot()
	return entries
}

func (dl *DBLedger) Snapshot() ([]models.AuditEntry, string) {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	out := make([]models.AuditEntry, len(dl.entries))
	copy(out, dl.entries)
	return out, dl.anchorHash
}

func (dl *DBLedger) AnchorHash() string {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	return dl.anchorHash
}

func (dl *DBLedger) VerifyChain() int {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	prevHash := dl.anchorHash
	for i, entry := range dl.entries {
		expected, err := attestChained(entry, prevHash)
		if err != nil || expected != entry.Attestation {
			return i
		}
		prevHash = entry.Attestation
	}
	return -1
}

func (dl *DBLedger) Close() {
	dl.stmt.Close()
	dl.db.Close()
}

// AsyncDBLedger is Mode B with Postgres: hash computed sync, DB write async.
type AsyncDBLedger struct {
	mu         sync.Mutex
	entries    []models.AuditEntry
	anchorHash string
	lastHash   string
	maxEntries int
	db         *sql.DB
	logger     *log.Logger
	clock      func() time.Time
	queue      chan models.AuditEntry
	closed     int32 // atomic flag: 1 = closed
	done       chan struct{}
	wg         sync.WaitGroup
	fallbacks  int64
	lifecycle  sync.RWMutex
}

// NewAsyncDBLedger creates a Mode B ledger with async Postgres persistence.
func NewAsyncDBLedger(dbDSN string, logWriter io.Writer, bufferSize int) (*AsyncDBLedger, error) {
	db, err := sql.Open("postgres", dbDSN)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(20)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureAuditSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	entries, anchorHash, lastHash, err := loadAuditEntries(db, defaultMaxEntries)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if logWriter == nil {
		logWriter = io.Discard
	}
	if bufferSize <= 0 {
		bufferSize = 10000
	}

	al := &AsyncDBLedger{
		entries:    entries,
		anchorHash: anchorHash,
		lastHash:   lastHash,
		maxEntries: defaultMaxEntries,
		db:         db,
		logger:     log.New(logWriter, "", 0),
		clock:      func() time.Time { return time.Now().UTC() },
		queue:      make(chan models.AuditEntry, bufferSize),
		done:       make(chan struct{}),
	}
	al.wg.Add(1)
	go al.worker()
	return al, nil
}

func (al *AsyncDBLedger) Record(entry models.AuditEntry) (models.AuditEntry, error) {
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
	if entry.ID == "" {
		entry.ID = entry.Component + "-" + al.clock().Format("20060102150405.000000000")
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = al.clock()
	}

	// Compute and append the chain synchronously. Only the DB write is async.
	al.mu.Lock()
	attestation, err := attestChained(entry, al.lastHash)
	if err != nil {
		al.mu.Unlock()
		return models.AuditEntry{}, err
	}
	entry.Attestation = attestation
	al.lastHash = attestation
	al.entries = append(al.entries, entry)
	if al.maxEntries > 0 && len(al.entries) > al.maxEntries {
		half := len(al.entries) / 2
		al.anchorHash = al.entries[half-1].Attestation
		al.entries = al.entries[half:]
	}

	// Keep sequencing locked through enqueue so DB persistence order matches
	// the attestation chain order.
	select {
	case al.queue <- entry:
		al.mu.Unlock()
	default:
		atomic.AddInt64(&al.fallbacks, 1)
		al.queue <- entry
		al.mu.Unlock()
	}
	return entry, nil
}

func (al *AsyncDBLedger) worker() {
	defer al.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]models.AuditEntry, 0, 1000)

	for {
		select {
		case entry := <-al.queue:
			batch = append(batch, entry)
			// Drain more
			for len(batch) < 1000 {
				select {
				case e := <-al.queue:
					batch = append(batch, e)
				default:
					goto flushDB
				}
			}
		flushDB:
			al.flushToDB(batch)
			batch = batch[:0]

		case <-ticker.C:
			for {
				select {
				case e := <-al.queue:
					batch = append(batch, e)
				default:
					goto tickFlush
				}
			}
		tickFlush:
			if len(batch) > 0 {
				al.flushToDB(batch)
				batch = batch[:0]
			}

		case <-al.done:
			close(al.queue)
			for e := range al.queue {
				batch = append(batch, e)
			}
			if len(batch) > 0 {
				al.flushToDB(batch)
			}
			return
		}
	}
}

func (al *AsyncDBLedger) flushToDB(batch []models.AuditEntry) {
	tx, err := al.db.Begin()
	if err != nil {
		al.logger.Printf("async audit begin transaction: %v", err)
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO audit_ledger
		(id, timestamp, timestamp_ns, agent_id, intent_fingerprint, action, component, status, details, attestation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`)
	if err != nil {
		tx.Rollback()
		al.logger.Printf("async audit prepare: %v", err)
		return
	}

	for _, entry := range batch {
		detailsJSON, _ := json.Marshal(entry.Details)
		if _, err := stmt.Exec(
			entry.ID, entry.Timestamp, entry.Timestamp.UnixNano(), entry.AgentID, entry.IntentFingerprint,
			entry.Action, entry.Component, entry.Status, detailsJSON, entry.Attestation,
		); err != nil {
			al.logger.Printf("async audit insert %s: %v", entry.ID, err)
			_ = stmt.Close()
			_ = tx.Rollback()
			return
		}
	}

	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		al.logger.Printf("async audit close statement: %v", err)
		return
	}
	if err := tx.Commit(); err != nil {
		al.logger.Printf("async audit commit: %v", err)
	}
}

func (al *AsyncDBLedger) Entries() []models.AuditEntry {
	entries, _ := al.Snapshot()
	return entries
}

func (al *AsyncDBLedger) Snapshot() ([]models.AuditEntry, string) {
	al.mu.Lock()
	defer al.mu.Unlock()
	out := make([]models.AuditEntry, len(al.entries))
	copy(out, al.entries)
	return out, al.anchorHash
}

func (al *AsyncDBLedger) AnchorHash() string {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.anchorHash
}

func (al *AsyncDBLedger) VerifyChain() int {
	al.mu.Lock()
	defer al.mu.Unlock()
	prevHash := al.anchorHash
	for i, entry := range al.entries {
		expected, err := attestChained(entry, prevHash)
		if err != nil || expected != entry.Attestation {
			return i
		}
		prevHash = entry.Attestation
	}
	return -1
}

func (al *AsyncDBLedger) Fallbacks() int64 { return atomic.LoadInt64(&al.fallbacks) }
func (al *AsyncDBLedger) Close() {
	al.lifecycle.Lock()
	atomic.StoreInt32(&al.closed, 1)
	close(al.done)
	al.lifecycle.Unlock()
	al.wg.Wait()
	al.db.Close()
}

func ensureAuditSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_ledger (
			sequence BIGSERIAL NOT NULL UNIQUE,
			id TEXT PRIMARY KEY,
			timestamp TIMESTAMPTZ NOT NULL,
			timestamp_ns BIGINT NOT NULL,
			agent_id TEXT NOT NULL,
			intent_fingerprint TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL,
			component TEXT NOT NULL,
			status TEXT NOT NULL,
			details JSONB NOT NULL DEFAULT '{}'::jsonb,
			attestation TEXT NOT NULL
		);
		ALTER TABLE audit_ledger
			ADD COLUMN IF NOT EXISTS sequence BIGSERIAL;
		ALTER TABLE audit_ledger
			ADD COLUMN IF NOT EXISTS timestamp_ns BIGINT;
		CREATE UNIQUE INDEX IF NOT EXISTS audit_ledger_sequence_idx
			ON audit_ledger (sequence);
	`)
	if err != nil {
		return fmt.Errorf("ensure audit schema: %w", err)
	}
	return nil
}

func loadAuditEntries(db *sql.DB, maxEntries int) ([]models.AuditEntry, string, string, error) {
	rows, err := db.Query(`
		SELECT id, timestamp_ns, agent_id, intent_fingerprint, action,
		       component, status, details, attestation
		FROM audit_ledger
		ORDER BY sequence ASC
	`)
	if err != nil {
		return nil, "", "", fmt.Errorf("load audit entries: %w", err)
	}
	defer rows.Close()

	entries := make([]models.AuditEntry, 0)
	anchorHash := GenesisHash
	lastHash := GenesisHash
	for rows.Next() {
		var entry models.AuditEntry
		var details []byte
		var timestampNS sql.NullInt64
		if err := rows.Scan(
			&entry.ID,
			&timestampNS,
			&entry.AgentID,
			&entry.IntentFingerprint,
			&entry.Action,
			&entry.Component,
			&entry.Status,
			&details,
			&entry.Attestation,
		); err != nil {
			return nil, "", "", fmt.Errorf("scan audit entry: %w", err)
		}
		if !timestampNS.Valid {
			return nil, "", "", fmt.Errorf(
				"load audit entry %s: timestamp_ns is missing; migrate or archive legacy audit rows",
				entry.ID,
			)
		}
		entry.Timestamp = time.Unix(0, timestampNS.Int64).UTC()
		if len(details) > 0 {
			if err := json.Unmarshal(details, &entry.Details); err != nil {
				return nil, "", "", fmt.Errorf("decode audit entry %s details: %w", entry.ID, err)
			}
		}
		expected, err := attestChained(entry, lastHash)
		if err != nil {
			return nil, "", "", fmt.Errorf("verify persisted audit entry %s: %w", entry.ID, err)
		}
		if expected != entry.Attestation {
			return nil, "", "", fmt.Errorf("verify persisted audit chain: entry %s is invalid", entry.ID)
		}
		entries = append(entries, entry)
		lastHash = entry.Attestation
		if maxEntries > 0 && len(entries) > maxEntries {
			half := len(entries) / 2
			anchorHash = entries[half-1].Attestation
			entries = entries[half:]
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", "", fmt.Errorf("iterate audit entries: %w", err)
	}
	return entries, anchorHash, lastHash, nil
}
