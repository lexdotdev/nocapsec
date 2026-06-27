package oast

import (
	"slices"
	"strings"
)

// SourceClass identifies callback source.
type SourceClass int

const (
	SourceTargetInfra SourceClass = iota
	SourceVerifierBrowser
	SourceNoise
)

// ClassifySource attributes a callback.
func ClassifySource(ix Interaction, targetIPs []string, verifierUA string) SourceClass {
	if verifierUA != "" && strings.Contains(ix.UserAgent, verifierUA) {
		return SourceVerifierBrowser
	}
	if slices.Contains(targetIPs, ix.SourceIP) {
		return SourceTargetInfra
	}
	return SourceNoise
}

// FilterByProtocol keeps expected protocols.
func FilterByProtocol(ixns []Interaction, expected []string) []Interaction {
	var out []Interaction
	for _, ix := range ixns {
		if slices.Contains(expected, ix.Protocol) {
			out = append(out, ix)
		}
	}
	return out
}

// RequireSourceNotVerifier keeps target callbacks.
func RequireSourceNotVerifier(ixns []Interaction, targetIPs []string, verifierUA string) []Interaction {
	var out []Interaction
	for _, ix := range ixns {
		if ClassifySource(ix, targetIPs, verifierUA) == SourceTargetInfra {
			out = append(out, ix)
		}
	}
	return out
}
