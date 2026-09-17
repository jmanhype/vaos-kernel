package agenticjwt

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

var checksumPattern = regexp.MustCompile(`^(?:sha256:)?[0-9a-f]{64}$`)

// NormalizePrompt applies the draft's deterministic prompt normalization.
func NormalizePrompt(prompt string) string {
	if prompt == "" {
		return ""
	}
	prompt = strings.ReplaceAll(prompt, "\r\n", "\n")
	lines := strings.Split(prompt, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

type checksumTool struct {
	Name        string `json:"name"`
	Signature   string `json:"signature"`
	Description string `json:"description"`
}

type checksumObject struct {
	ID     string         `json:"id"`
	Prompt string         `json:"prompt"`
	Tools  []checksumTool `json:"tools"`
	Config map[string]any `json:"config"`
}

// CanonicalChecksum computes the P0 SHA-256 agent checksum.
//
// The wire object follows draft section 5.3.2's Go reference shape:
// {"id", "prompt", "tools":[{"name","signature","description"}], "config"}.
// Configuration is serialized with RFC 8785 JCS, including ECMAScript number
// serialization and UTF-16 code-unit property ordering.
func CanonicalChecksum(spec AgentSpec) (string, error) {
	if err := ValidateAgentSpec(spec); err != nil {
		return "", err
	}
	tools := make([]checksumTool, 0, len(spec.Tools))
	for _, tool := range spec.Tools {
		tools = append(tools, checksumTool{
			Name:        tool.Name,
			Signature:   tool.Signature,
			Description: tool.Description,
		})
	}
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].Name == tools[j].Name {
			return tools[i].Signature+tools[i].Description < tools[j].Signature+tools[j].Description
		}
		return tools[i].Name < tools[j].Name
	})

	object := checksumObject{
		ID:     spec.AgentID,
		Prompt: NormalizePrompt(spec.Prompt),
		Tools:  tools,
		Config: spec.Configuration,
	}
	if object.Config == nil {
		object.Config = map[string]any{}
	}
	encoded, err := canonicalJSON(object)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// ValidateChecksumFormat accepts either bare lowercase hex or "sha256:<hex>".
func ValidateChecksumFormat(checksum string) error {
	if checksumPattern.MatchString(checksum) {
		return nil
	}
	return invalidRequest("checksum must be lowercase SHA-256 hex, optionally prefixed with sha256:")
}

// NormalizeChecksum removes the optional sha256 prefix.
func NormalizeChecksum(checksum string) (string, error) {
	if err := ValidateChecksumFormat(checksum); err != nil {
		return "", err
	}
	return strings.TrimPrefix(checksum, "sha256:"), nil
}

func checksumEqual(a, b string) bool {
	a, _ = NormalizeChecksum(a)
	b, _ = NormalizeChecksum(b)
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
