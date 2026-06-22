package validators

import (
	"testing"

	"github.com/lexdotdev/nocapsec/internal/httpx"
)

func TestFingerprintStatusDifference(t *testing.T) {
	a := Fingerprint(&httpx.Capture{StatusCode: 200, RespBody: []byte("ok")})
	b := Fingerprint(&httpx.Capture{StatusCode: 404, RespBody: []byte("ok")})

	if Similar(a, b, []DiffDimension{DimStatus}) {
		t.Fatal("different status codes should not be similar")
	}
	if !Similar(a, a, []DiffDimension{DimStatus}) {
		t.Fatal("same capture should be similar")
	}
}

func TestFingerprintBodyHashMasking(t *testing.T) {
	// UUID-only changes are masked.
	bodyA := []byte(`<p>token: 550e8400-e29b-41d4-a716-446655440000</p>`)
	bodyB := []byte(`<p>token: 6ba7b810-9dad-11d1-80b4-00c04fd430c8</p>`)

	a := Fingerprint(&httpx.Capture{StatusCode: 200, RespBody: bodyA})
	b := Fingerprint(&httpx.Capture{StatusCode: 200, RespBody: bodyB})

	if !Similar(a, b, []DiffDimension{DimBodyHashFuzzy}) {
		t.Fatal("bodies differing only by UUID should be similar after masking")
	}
}

func TestFingerprintBodyHashRealDifference(t *testing.T) {
	a := Fingerprint(&httpx.Capture{StatusCode: 200, RespBody: []byte("Product found: Widget A")})
	b := Fingerprint(&httpx.Capture{StatusCode: 200, RespBody: []byte("No results")})

	if Similar(a, b, []DiffDimension{DimBodyHashFuzzy}) {
		t.Fatal("genuinely different bodies should not be similar")
	}
}

func TestContentLengthBucket(t *testing.T) {
	tests := []struct {
		name  string
		sizeA int
		sizeB int
		same  bool
	}{
		{"both tiny", 10, 50, true},
		{"both medium", 2000, 3000, true},
		{"tiny vs large", 10, 5000, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := Fingerprint(&httpx.Capture{StatusCode: 200, RespBody: make([]byte, tc.sizeA)})
			b := Fingerprint(&httpx.Capture{StatusCode: 200, RespBody: make([]byte, tc.sizeB)})
			got := Similar(a, b, []DiffDimension{DimContentLengthBucket})
			if got != tc.same {
				t.Fatalf("Similar(len=%d, len=%d) = %v, want %v", tc.sizeA, tc.sizeB, got, tc.same)
			}
		})
	}
}

func TestSemanticMarkers(t *testing.T) {
	bodyWithError := []byte(`<html><title>Error</title><p>access denied</p></html>`)
	bodyNormal := []byte(`<html><title>Products</title><p>Widget A</p></html>`)

	a := Fingerprint(&httpx.Capture{StatusCode: 200, RespBody: bodyWithError})
	b := Fingerprint(&httpx.Capture{StatusCode: 200, RespBody: bodyNormal})

	if Similar(a, b, []DiffDimension{DimSemanticMarkers}) {
		t.Fatal("error page vs normal page should differ in semantic markers")
	}
}

func TestParseDimensions(t *testing.T) {
	raw := []string{"status", "body_hash_fuzzy", "unknown_dim", "content_length_bucket"}
	dims := ParseDimensions(raw)
	if len(dims) != 3 {
		t.Fatalf("got %d dims, want 3 (unknown_dim dropped)", len(dims))
	}
}

func TestMaskDynamic(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			"uuid masked",
			`id: 550e8400-e29b-41d4-a716-446655440000 done`,
			`id: __MASKED__ done`,
		},
		{
			"unix epoch masked",
			`ts=1718812345 end`,
			`ts=__MASKED__ end`,
		},
		{
			"iso datetime masked",
			`at 2024-06-19T14:30:00Z done`,
			`at __MASKED__Z done`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := string(maskDynamic([]byte(tc.input)))
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMultiDimensionSimilarity(t *testing.T) {
	dims := []DiffDimension{DimStatus, DimBodyHashFuzzy, DimContentLengthBucket}

	a := Fingerprint(&httpx.Capture{StatusCode: 200, RespBody: []byte("same content here")})
	b := Fingerprint(&httpx.Capture{StatusCode: 200, RespBody: []byte("same content here")})
	if !Similar(a, b, dims) {
		t.Fatal("identical captures should be similar on all dims")
	}

	// Change status -> no longer similar.
	c := Fingerprint(&httpx.Capture{StatusCode: 500, RespBody: []byte("same content here")})
	if Similar(a, c, dims) {
		t.Fatal("different status should break similarity")
	}
}
