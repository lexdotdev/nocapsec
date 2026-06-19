package validators

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/httpx"
)

// formatRedirects renders hops as "<status> <from> -> <to>".
func formatRedirects(hops []httpx.RedirectHop) []string {
	if len(hops) == 0 {
		return nil
	}
	out := make([]string, len(hops))
	for i, h := range hops {
		out[i] = fmt.Sprintf("%d %s -> %s", h.StatusCode, h.From, h.To)
	}
	return out
}

// DiffDimension names a comparison axis for differential analysis.
type DiffDimension string

const (
	DimStatus              DiffDimension = "status"
	DimBodyHashFuzzy       DiffDimension = "body_hash_fuzzy"
	DimContentLengthBucket DiffDimension = "content_length_bucket"
	DimSemanticMarkers     DiffDimension = "semantic_markers"
)

// ResponseFingerprint is a normalized summary of a response for comparison.
type ResponseFingerprint struct {
	Status            int
	BodyHashFuzzy     [sha256.Size]byte
	ContentLenBucket  int
	SemanticMarkerSet map[string]bool
}

// Fingerprint computes a normalized response summary with dynamic content masked.
func Fingerprint(c *httpx.Capture) ResponseFingerprint {
	masked := maskDynamic(c.RespBody)
	return ResponseFingerprint{
		Status:            c.StatusCode,
		BodyHashFuzzy:     sha256.Sum256(masked),
		ContentLenBucket:  lengthBucket(len(c.RespBody)),
		SemanticMarkerSet: extractSemanticMarkers(c.RespBody),
	}
}

// Similar reports whether two fingerprints match on all requested dimensions.
func Similar(a, b ResponseFingerprint, dims []DiffDimension) bool {
	for _, d := range dims {
		if !dimensionEqual(a, b, d) {
			return false
		}
	}
	return true
}

func dimensionEqual(a, b ResponseFingerprint, d DiffDimension) bool {
	switch d {
	case DimStatus:
		return a.Status == b.Status
	case DimBodyHashFuzzy:
		return a.BodyHashFuzzy == b.BodyHashFuzzy
	case DimContentLengthBucket:
		return a.ContentLenBucket == b.ContentLenBucket
	case DimSemanticMarkers:
		return markerSetsEqual(a.SemanticMarkerSet, b.SemanticMarkerSet)
	default:
		return true
	}
}

func markerSetsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// ParseDimensions converts wire strings to typed dimensions, ignoring unknown.
func ParseDimensions(raw []string) []DiffDimension {
	dims := make([]DiffDimension, 0, len(raw))
	for _, s := range raw {
		switch DiffDimension(s) {
		case DimStatus, DimBodyHashFuzzy, DimContentLengthBucket, DimSemanticMarkers:
			dims = append(dims, DiffDimension(s))
		}
	}
	return dims
}

// lengthBucket groups response sizes into log-scale buckets so small
// volatile differences (ads, tokens) do not trigger false differentials.
func lengthBucket(n int) int {
	switch {
	case n < 256:
		return 0
	case n < 1024:
		return 1
	case n < 4096:
		return 2
	case n < 16384:
		return 3
	case n < 65536:
		return 4
	case n < 262144:
		return 5
	default:
		return 6
	}
}

// dynamicPatterns matches tokens/timestamps/UUIDs/CSRF that vary per-request.
var dynamicPatterns = regexp.MustCompile(strings.Join([]string{
	`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, // UUID
	`\b\d{10,13}\b`,                                     // unix epoch (seconds or millis)
	`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`,               // ISO 8601 datetime prefix
	`csrf[_-]?token["':=\s]+["']?[A-Za-z0-9+/=_-]{16,}`, // CSRF tokens
	`nonce["':=\s]+["']?[A-Za-z0-9+/=_-]{8,}`,           // nonce values
}, "|"))

// maskDynamic replaces volatile tokens so fuzzy hashing is stable.
func maskDynamic(body []byte) []byte {
	return dynamicPatterns.ReplaceAll(body, []byte("__MASKED__"))
}

// semanticMarkerPatterns capture structural HTML/error signals that indicate
// page meaning beyond raw content (e.g. error messages, login forms).
var semanticMarkerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`),
	regexp.MustCompile(`(?i)(?:error|exception|warning|denied|forbidden|not found|unauthorized)`),
	regexp.MustCompile(`(?i)<form[^>]*>`),
	regexp.MustCompile(`(?i)<input[^>]*type=["']?(?:password|hidden)`),
	regexp.MustCompile(`(?i)(?:login|sign.?in|log.?in)`),
}

// extractSemanticMarkers returns a set of structural signals found in body.
func extractSemanticMarkers(body []byte) map[string]bool {
	markers := map[string]bool{}
	for i, pat := range semanticMarkerPatterns {
		if pat.Match(body) {
			// Use pattern index as key for stable comparison.
			markers[semanticMarkerNames[i]] = true
		}
	}
	return markers
}

var semanticMarkerNames = []string{
	"title", "error_text", "form", "password_input", "login_text",
}
