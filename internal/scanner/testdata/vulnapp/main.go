// Package main is a deliberately quantum-vulnerable fixture for scanner tests.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
)

func generateKeys() {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = rsaKey
	_ = ecKey
}

func tlsSetup() *tls.Config {
	// Explicit CurvePreferences without hybrid group: silently disables PQ KEX.
	return &tls.Config{
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
		MinVersion:       tls.VersionTLS12,
	}
}

func tlsReady() *tls.Config {
	// No pin + TLS 1.3 floor on go>=1.24: already PQ-ready, nothing to do.
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

func tlsNoFloor() *tls.Config {
	// No pin but no TLS 1.3 floor: hybrid KEX is default, yet TLS 1.2
	// fallback has no PQ KEX — needs MinVersion raise; CipherSuites noted.
	return &tls.Config{
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
}

func weakHash(data []byte) string {
	return fmt.Sprintf("%x", md5.Sum(data))
}
