package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// domainTag is the ASCII string from spec §2. Its bytes prefix the signed
// message. Exactly 19 bytes.
const domainTag = "aft::seal-share::v1"

// Share models a seal share (spec §1). The vectors encode seal_hash,
// public_key, and signature as lowercase hex strings.
type Share struct {
	MemberIndex uint32 `json:"member_index"`
	SealIndex   uint64 `json:"seal_index"`
	SealHash    string `json:"seal_hash"`
	PublicKey   string `json:"public_key"`
	Signature   string `json:"signature"`
}

// RejectVector is an accept-shaped share with a named failure case.
type RejectVector struct {
	Case string `json:"case"`
	Share
}

// Vectors is the top-level conformance file.
type Vectors struct {
	DomainTag string         `json:"domain_tag"`
	Scheme    string         `json:"scheme"`
	Message   string         `json:"message"`
	Accept    []Share        `json:"accept"`
	Reject    []RejectVector `json:"reject"`
	Extract   struct {
		CertX             []Share  `json:"cert_x"`
		CertY             []Share  `json:"cert_y"`
		ExpectedOffenders []uint32 `json:"expected_offenders"`
	} `json:"extraction"`
}

// buildMessage constructs the 59-byte domain-separated message of spec §2:
// domain-tag ASCII bytes ‖ seal_index as 8-byte big-endian ‖ 32-byte
// seal_hash. sealHash must already be the 32 raw bytes.
func buildMessage(sealIndex uint64, sealHash []byte) []byte {
	msg := make([]byte, 0, len(domainTag)+8+32)
	msg = append(msg, []byte(domainTag)...)
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], sealIndex)
	msg = append(msg, be[:]...)
	msg = append(msg, sealHash...)
	return msg
}

// verifySealShare implements spec §4. Returns true = accept, false = reject.
// A malformed public_key length (!=32), signature length (!=64), or
// seal_hash length (!=32) is a reject. Otherwise: standard RFC 8032
// Ed25519 verification over the §2 message.
func verifySealShare(s Share) bool {
	pub, err := hex.DecodeString(s.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize { // 32
		return false
	}
	sig, err := hex.DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize { // 64
		return false
	}
	sealHash, err := hex.DecodeString(s.SealHash)
	if err != nil || len(sealHash) != 32 {
		return false
	}
	msg := buildMessage(s.SealIndex, sealHash)
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// extractDoubleSigners implements spec §5. If any share in either cert
// fails §4 verification, it returns an error. Otherwise it returns the
// sorted, de-duplicated member indices that signed conflicting seal
// hashes for the same seal index across the two certs.
func extractDoubleSigners(certX, certY []Share) ([]uint32, error) {
	for i, s := range certX {
		if !verifySealShare(s) {
			return nil, fmt.Errorf("cert_x share %d (member_index %d) failed verification", i, s.MemberIndex)
		}
	}
	for i, s := range certY {
		if !verifySealShare(s) {
			return nil, fmt.Errorf("cert_y share %d (member_index %d) failed verification", i, s.MemberIndex)
		}
	}

	offenderSet := map[uint32]struct{}{}
	for _, x := range certX {
		for _, y := range certY {
			if x.MemberIndex == y.MemberIndex &&
				x.SealIndex == y.SealIndex &&
				x.SealHash != y.SealHash {
				offenderSet[x.MemberIndex] = struct{}{}
			}
		}
	}

	offenders := make([]uint32, 0, len(offenderSet))
	for m := range offenderSet {
		offenders = append(offenders, m)
	}
	sort.Slice(offenders, func(i, j int) bool { return offenders[i] < offenders[j] })
	return offenders, nil
}

func equalUint32Slices(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func main() {
	// The vectors are a sibling file in the same directory.
	const vectorsPath = "conformance_vectors.json"
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", vectorsPath, err)
		os.Exit(2)
	}
	var v Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		fmt.Fprintf(os.Stderr, "cannot parse vectors: %v\n", err)
		os.Exit(2)
	}

	allPass := true

	// --- accept group: every share must accept ---
	acceptPass, acceptTotal := 0, len(v.Accept)
	for i, s := range v.Accept {
		if verifySealShare(s) {
			acceptPass++
		} else {
			allPass = false
			fmt.Printf("  ACCEPT vector %d (member_index %d, seal_index %d): FAIL — verifier rejected an accept vector\n", i, s.MemberIndex, s.SealIndex)
		}
	}
	if acceptPass == acceptTotal {
		fmt.Printf("accept group: PASS (%d/%d accepted)\n", acceptPass, acceptTotal)
	} else {
		fmt.Printf("accept group: FAIL (%d/%d accepted)\n", acceptPass, acceptTotal)
	}

	// --- reject group: every share must reject ---
	rejectPass, rejectTotal := 0, len(v.Reject)
	for _, rv := range v.Reject {
		if !verifySealShare(rv.Share) {
			rejectPass++
		} else {
			allPass = false
			fmt.Printf("  REJECT vector case %q (member_index %d): FAIL — verifier ACCEPTED a reject vector (CRITICAL)\n", rv.Case, rv.MemberIndex)
		}
	}
	if rejectPass == rejectTotal {
		fmt.Printf("reject group: PASS (%d/%d rejected)\n", rejectPass, rejectTotal)
	} else {
		fmt.Printf("reject group: FAIL (%d/%d rejected)\n", rejectPass, rejectTotal)
	}

	// --- extraction case ---
	offenders, err := extractDoubleSigners(v.Extract.CertX, v.Extract.CertY)
	if err != nil {
		allPass = false
		fmt.Printf("extraction: FAIL — unexpected error: %v\n", err)
	} else if equalUint32Slices(offenders, v.Extract.ExpectedOffenders) {
		fmt.Printf("extraction: PASS (offenders %v == expected %v)\n", offenders, v.Extract.ExpectedOffenders)
	} else {
		allPass = false
		fmt.Printf("extraction: FAIL (offenders %v != expected %v)\n", offenders, v.Extract.ExpectedOffenders)
	}

	// --- summary ---
	fmt.Println("----")
	if allPass {
		fmt.Printf("SUMMARY: ALL PASS — accept %d/%d, reject %d/%d, extraction ok\n",
			acceptPass, acceptTotal, rejectPass, rejectTotal)
		os.Exit(0)
	}
	fmt.Printf("SUMMARY: FAILURES PRESENT — accept %d/%d, reject %d/%d\n",
		acceptPass, acceptTotal, rejectPass, rejectTotal)
	os.Exit(1)
}
