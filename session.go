package main

import "hoot/nip46"

// Global NIP-46 session and local key
var nip46Session *nip46.Session

var localPrivateKey string

// endRemoteSession closes and forgets any NIP-46 session. publishPostTUI
// prefers nip46Session over localPrivateKey, so a session left over from an
// abandoned QR attempt (or a previous Amber login) would otherwise hijack
// signing for a local-key login.
func endRemoteSession() {
	if nip46Session != nil {
		nip46Session.Close()
		nip46Session = nil
	}
}

// useLocalKey switches the process to signing with a local hex key.
func useLocalKey(sk string) {
	endRemoteSession()
	localPrivateKey = sk
}
