package oast

import "strings"

// SourceClass categorizes a callback's origin.
type SourceClass int

const (
	// SourceTargetInfra: from target infrastructure.
	SourceTargetInfra SourceClass = iota
	// SourceVerifierBrowser: from verifier browser.
	SourceVerifierBrowser
	// SourceNoise: unattributable third-party callback.
	SourceNoise
)

// ClassifySource attributes a callback by IP, UA.
func ClassifySource(ix Interaction, targetIPs []string, verifierUA string) SourceClass {
	for _, s := range targetIPs {
		if ix.SourceIP == s {
			return SourceTargetInfra
		}
	}
	if verifierUA != "" && strings.Contains(ix.UserAgent, verifierUA) {
		return SourceVerifierBrowser
	}
	return SourceNoise
}

// FilterByProtocol keeps expected protocols.
func FilterByProtocol(ixns []Interaction, expected []string) []Interaction {
	set := make(map[string]struct{}, len(expected))
	for _, p := range expected {
		set[p] = struct{}{}
	}
	var out []Interaction
	for _, ix := range ixns {
		if _, ok := set[ix.Protocol]; ok {
			out = append(out, ix)
		}
	}
	return out
}

// RequireSourceNotVerifier drops verifier + noise.
// Source attribution: not verifier.
func RequireSourceNotVerifier(ixns []Interaction, targetIPs []string, verifierUA string) []Interaction {
	var out []Interaction
	for _, ix := range ixns {
		cls := ClassifySource(ix, targetIPs, verifierUA)
		if cls != SourceVerifierBrowser && cls != SourceNoise {
			out = append(out, ix)
		}
	}
	return out
}
