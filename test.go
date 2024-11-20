package main

import (
	"crypto/sha256"
	"encoding/binary"
	"log"
)

// Stolen straight from https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.html#hybrid-qr-initiated

var assignedTunnelServerDomains = []string{"cable.ua5v.com", "cable.auth.com"}

func decodeTunnelServerDomain(encoded uint16) (string, bool) {
	if encoded < 256 {
		if int(encoded) >= len(assignedTunnelServerDomains) {
			return "", false
		}
		return assignedTunnelServerDomains[encoded], true
	}

	shaInput := []byte{
		0x63, 0x61, 0x42, 0x4c, 0x45, 0x76, 0x32, 0x20,
		0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x73,
		0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x64, 0x6f,
		0x6d, 0x61, 0x69, 0x6e,
	}
	shaInput = append(shaInput, byte(encoded), byte(encoded>>8), 0)
	digest := sha256.Sum256(shaInput)

	v := binary.LittleEndian.Uint64(digest[:8])
	log.Println(v, v&3)
	tldIndex := uint(v & 3)
	v >>= 2

	ret := "cable."
	const base32Chars = "abcdefghijklmnopqrstuvwxyz234567"
	for v != 0 {
		ret += string(base32Chars[v&31])
		v >>= 5
	}

	tlds := []string{".com", ".org", ".net", ".info"}
	ret += tlds[tldIndex]

	return ret, true
}

func main() {
	res, _ := decodeTunnelServerDomain(0x0100)
	log.Println(res)
}
