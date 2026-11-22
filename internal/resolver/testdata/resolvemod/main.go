// resolvemod is the resolver test fixture: one function per resolution case.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"os"
	"strconv"
)

const namedBits = 2048

func litBits() { _, _ = rsa.GenerateKey(rand.Reader, 1024) }

func namedConstBits() { _, _ = rsa.GenerateKey(rand.Reader, namedBits) }

func varBits() {
	b := 3072
	_, _ = rsa.GenerateKey(rand.Reader, b)
}

func envBits() {
	b, _ := strconv.Atoi(os.Getenv("RSA_BITS"))
	_, _ = rsa.GenerateKey(rand.Reader, b)
}

func paramBits(bits int) { _, _ = rsa.GenerateKey(rand.Reader, bits) }

func curveLit() { _, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func signGenerated() {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, _ = rsa.SignPKCS1v15(rand.Reader, k, 0, nil)
}

func signLoaded(pemBytes []byte) {
	block, _ := pem.Decode(pemBytes)
	k, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	_, _ = rsa.SignPKCS1v15(rand.Reader, k, 0, nil)
}

func tlsExplicitNoPQC() *tls.Config {
	return &tls.Config{
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

func tlsDefaults() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

func keyToDisk() {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := x509.MarshalPKCS1PrivateKey(k)
	buf := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	_ = os.WriteFile("key.pem", buf, 0o600)
}

func ciphertextToNet(conn net.Conn, pub *rsa.PublicKey, msg []byte) {
	ct, _ := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	_, _ = conn.Write(ct)
}

func signatureLocal(k *rsa.PrivateKey, digest []byte) bool {
	sig, _ := rsa.SignPKCS1v15(rand.Reader, k, 0, digest)
	return len(sig) > 0
}

func helperBits() int { return 2048 }

func bitsViaHelper() { _, _ = rsa.GenerateKey(rand.Reader, helperBits()) }

// UncalledGen has no callers: the parameter must stay unresolved.
func UncalledGen(bits int) { _, _ = rsa.GenerateKey(rand.Reader, bits) }

func makeCiphertext(pub *rsa.PublicKey, msg []byte) []byte {
	ct, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
	return ct
}

func persistCiphertext(pub *rsa.PublicKey, msg []byte) {
	_ = os.WriteFile("ct.bin", makeCiphertext(pub, msg), 0o600)
}

func b64KeyToDisk() {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := x509.MarshalPKCS1PrivateKey(k)
	s := base64.StdEncoding.EncodeToString(der)
	_ = os.WriteFile("key.b64", []byte(s), 0o600)
}

func sharedKeyLifecycle() {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, _ = rsa.SignPKCS1v15(rand.Reader, k, 0, nil)
	der := x509.MarshalPKCS1PrivateKey(k)
	_ = os.WriteFile("shared.der", der, 0o600)
}

func closureKeyToDisk() {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := x509.MarshalPKCS1PrivateKey(k)
	write := func() { _ = os.WriteFile("closure.der", der, 0o600) }
	write()
}

// defaultPrefs is the caddy-style pattern: a package-level default that
// reaches CurvePreferences through a local and a branch.
var defaultPrefs = []tls.CurveID{tls.X25519, tls.CurveP256}

func tlsFromConfig(names []string) *tls.Config {
	curves := defaultPrefs
	if len(names) > 0 {
		curves = nil
	}
	c := new(tls.Config)
	c.CurvePreferences = curves
	return c
}

func main() {
	litBits()
	namedConstBits()
	varBits()
	envBits()
	paramBits(4096)
	curveLit()
	signGenerated()
	signLoaded(nil)
	_ = tlsExplicitNoPQC()
	_ = tlsDefaults()
	keyToDisk()
	ciphertextToNet(nil, nil, nil)
	_ = signatureLocal(nil, nil)
	bitsViaHelper()
	persistCiphertext(nil, nil)
	b64KeyToDisk()
	closureKeyToDisk()
	sharedKeyLifecycle()
	_ = tlsFromConfig(nil)
}
