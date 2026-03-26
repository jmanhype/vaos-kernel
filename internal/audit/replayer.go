package audit

import "vaos-kernel/pkg/models"

// ReplayResult summarises a full-chain replay verification.
type ReplayResult struct {
	EntryCount       int    `json:"entry_count"`
	ChainStatus      string `json:"chain_status"`
	BrokenAtIndex    int    `json:"broken_at_index"`
	SigStatus        string `json:"sig_status"`
	SigFailedAtID    string `json:"sig_failed_at_id"`
	SigVerifiedCount int    `json:"sig_verified_count"`
}

// Replay walks entries recomputing the hash chain and optionally verifying
// signatures. sigFn returns the stored signature for an entry (empty = skip).
// verifyFn checks the raw attestation bytes against a hex signature.
// Either may be nil to skip signature verification entirely.
func Replay(
	entries  []models.AuditEntry,
	sigFn    func(models.AuditEntry) string,
	verifyFn func(data []byte, sigHex string) bool,
) ReplayResult {
	res := ReplayResult{
		EntryCount:    len(entries),
		ChainStatus:   "ok",
		BrokenAtIndex: -1,
		SigStatus:     "skipped",
	}

	if len(entries) == 0 {
		return res
	}

	prevHash := GenesisHash

	for i, e := range entries {
		if i == 0 {
			expected, err := attestChained(e, prevHash)
			if err != nil || expected != e.Attestation {
				prevHash = e.Attestation
				continue
			}
			prevHash = e.Attestation
			continue
		}
		expected, err := attestChained(e, prevHash)
		if err != nil || expected != e.Attestation {
			res.ChainStatus = "broken"
			res.BrokenAtIndex = i
			break
		}
		prevHash = e.Attestation
	}

	if sigFn == nil || verifyFn == nil {
		return res
	}

	res.SigStatus = "ok"
	for _, e := range entries {
		sig := sigFn(e)
		if sig == "" {
			continue
		}
		if verifyFn([]byte(e.Attestation), sig) {
			res.SigVerifiedCount++
		} else {
			res.SigStatus = "failed"
			res.SigFailedAtID = e.ID
			break
		}
	}
	return res
}
