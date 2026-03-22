package audit

import (
	"database/sql"
	"encoding/json"
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
	mu       sync.Mutex
	entries  []models.AuditEntry
	lastHash string
	db       *sql.DB
	logger   *log.Logger
	clock    func() time.Time
	stmt     *sql.Stmt
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
		return nil, err
	}

	stmt, err := db.Prepare(`INSERT INTO audit_ledger
		(id, timestamp, agent_id, intent_fingerprint, action, component, status, details, attestation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`)
	if err != nil {
		return nil, err
	}

	if logWriter == nil {
		logWriter = io.Discard
	}

	return &DBLedger{
		lastHash: GenesisHash,
		db:       db,
		logger:   log.New(logWriter, "", 0),
		clock:    func() time.Time { return time.Now().UTC() },
		stmt:     stmt,
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
		entry.ID, entry.Timestamp, entry.AgentID, entry.IntentFingerprint,
		entry.Action, entry.Component, entry.Status, detailsJSON, entry.Attestation,
	)
	if err != nil {
		dl.mu.Unlock()
		return models.AuditEntry{}, err
	}

	dl.lastHash = attestation
	dl.entries = append(dl.entries, entry)
	dl.mu.Unlock()

	return entry, nil
}

func (dl *DBLedger) Entries() []models.AuditEntry {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	out := make([]models.AuditEntry, len(dl.entries))
	copy(out, dl.entries)
	return out
}

func (dl *DBLedger) VerifyChain() int {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	prevHash := GenesisHash
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
	mu        sync.Mutex
	entries   []models.AuditEntry
	lastHash  string
	db        *sql.DB
	logger    *log.Logger
	clock     func() time.Time
	queue     chan models.AuditEntry
	done      chan struct{}
	wg        sync.WaitGroup
	fallbacks int64
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
		return nil, err
	}
	if logWriter == nil {
		logWriter = io.Discard
	}
	if bufferSize <= 0 {
		bufferSize = 10000
	}

	al := &AsyncDBLedger{
		lastHash: GenesisHash,
		db:       db,
		logger:   log.New(logWriter, "", 0),
		clock:    func() time.Time { return time.Now().UTC() },
		queue:    make(chan models.AuditEntry, bufferSize),
		done:     make(chan struct{}),
	}
	al.wg.Add(1)
	go al.worker()
	return al, nil
}

func (al *AsyncDBLedger) Record(entry models.AuditEntry) (models.AuditEntry, error) {
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

	select {
	case al.queue <- entry:
		return entry, nil
	default:
		atomic.AddInt64(&al.fallbacks, 1)
		return al.syncWrite(entry)
	}
}

func (al *AsyncDBLedger) syncWrite(entry models.AuditEntry) (models.AuditEntry, error) {
	al.mu.Lock()
	attestation, err := attestChained(entry, al.lastHash)
	if err != nil {
		al.mu.Unlock()
		return models.AuditEntry{}, err
	}
	entry.Attestation = attestation
	detailsJSON, _ := json.Marshal(entry.Details)
	_, err = al.db.Exec(`INSERT INTO audit_ledger
		(id, timestamp, agent_id, intent_fingerprint, action, component, status, details, attestation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		entry.ID, entry.Timestamp, entry.AgentID, entry.IntentFingerprint,
		entry.Action, entry.Component, entry.Status, detailsJSON, entry.Attestation)
	if err != nil {
		al.mu.Unlock()
		return models.AuditEntry{}, err
	}
	al.lastHash = attestation
	al.entries = append(al.entries, entry)
	al.mu.Unlock()
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
	al.mu.Lock()
	tx, err := al.db.Begin()
	if err != nil {
		al.mu.Unlock()
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO audit_ledger
		(id, timestamp, agent_id, intent_fingerprint, action, component, status, details, attestation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`)
	if err != nil {
		tx.Rollback()
		al.mu.Unlock()
		return
	}

	for i := range batch {
		attestation, err := attestChained(batch[i], al.lastHash)
		if err != nil {
			continue
		}
		batch[i].Attestation = attestation
		al.lastHash = attestation
		al.entries = append(al.entries, batch[i])

		detailsJSON, _ := json.Marshal(batch[i].Details)
		stmt.Exec(
			batch[i].ID, batch[i].Timestamp, batch[i].AgentID, batch[i].IntentFingerprint,
			batch[i].Action, batch[i].Component, batch[i].Status, detailsJSON, batch[i].Attestation)
	}

	stmt.Close()
	tx.Commit()
	al.mu.Unlock()
}

func (al *AsyncDBLedger) Entries() []models.AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()
	out := make([]models.AuditEntry, len(al.entries))
	copy(out, al.entries)
	return out
}

func (al *AsyncDBLedger) VerifyChain() int {
	al.mu.Lock()
	defer al.mu.Unlock()
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

func (al *AsyncDBLedger) Fallbacks() int64 { return atomic.LoadInt64(&al.fallbacks) }
func (al *AsyncDBLedger) Close()           { close(al.done); al.wg.Wait(); al.db.Close() }
