package validators

import (
	"crypto/sha256"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/httpx"
)

// formatRedirects renders redirect hops.
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

// DiffDimension names a differential axis.
type DiffDimension string

const (
	DimStatus              DiffDimension = "status"
	DimBodyHashFuzzy       DiffDimension = "body_hash_fuzzy"
	DimContentLengthBucket DiffDimension = "content_length_bucket"
	DimSemanticMarkers     DiffDimension = "semantic_markers"
)

// ResponseFingerprint normalizes a response.
type ResponseFingerprint struct {
	Status            int
	BodyHashFuzzy     [sha256.Size]byte
	ContentLenBucket  int
	SemanticMarkerSet map[string]bool
}

// Fingerprint masks dynamic content.
func Fingerprint(c *httpx.Capture) ResponseFingerprint {
	masked := maskDynamic(c.RespBody)
	return ResponseFingerprint{
		Status:            c.StatusCode,
		BodyHashFuzzy:     sha256.Sum256(masked),
		ContentLenBucket:  lengthBucket(len(c.RespBody)),
		SemanticMarkerSet: extractSemanticMarkers(c.RespBody),
	}
}

// Similar compares selected dimensions.
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
		// Marker values are always true.
		return maps.Equal(a.SemanticMarkerSet, b.SemanticMarkerSet)
	default:
		return true
	}
}

// ParseDimensions maps wire strings to dimensions.
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

// unionDims adds any missing required dimension.
func unionDims(dims []DiffDimension, required ...DiffDimension) []DiffDimension {
	out := slices.Clone(dims)
	for _, r := range required {
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// dimStrings returns wire values.
func dimStrings(dims []DiffDimension) []string {
	out := make([]string, len(dims))
	for i, d := range dims {
		out[i] = string(d)
	}
	return out
}

// lengthBucket absorbs size noise.
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

// dynamicPatterns matches volatile tokens.
var dynamicPatterns = regexp.MustCompile(strings.Join([]string{
	`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	`\b\d{10,13}\b`,
	`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`,
	`csrf[_-]?token["':=\s]+["']?[A-Za-z0-9+/=_-]{16,}`,
	`nonce["':=\s]+["']?[A-Za-z0-9+/=_-]{8,}`,
}, "|"))

// maskDynamic masks volatile tokens for hashing.
func maskDynamic(body []byte) []byte {
	return dynamicPatterns.ReplaceAll(body, []byte("__MASKED__"))
}

// semanticMarkerPatterns match coarse signals.
var semanticMarkerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`),
	regexp.MustCompile(`(?i)(?:error|exception|warning|denied|forbidden|not found|unauthorized)`),
	regexp.MustCompile(`(?i)<form[^>]*>`),
	regexp.MustCompile(`(?i)<input[^>]*type=["']?(?:password|hidden)`),
	regexp.MustCompile(`(?i)(?:login|sign.?in|log.?in)`),
}

// extractSemanticMarkers returns body signals.
func extractSemanticMarkers(body []byte) map[string]bool {
	markers := map[string]bool{}
	for i, pat := range semanticMarkerPatterns {
		if pat.Match(body) {
			// Stable comparison key.
			markers[semanticMarkerNames[i]] = true
		}
	}
	return markers
}

var semanticMarkerNames = []string{
	"title", "error_text", "form", "password_input", "login_text",
}
