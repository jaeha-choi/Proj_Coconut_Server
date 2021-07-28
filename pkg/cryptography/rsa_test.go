package cryptography

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"os"
	"testing"
)

func init() {
	log.Init(os.Stdout, log.DEBUG)
}

func TestCreateRSAKey(t *testing.T) {
	//t.Cleanup(func() {
	//	pubFileN := "key.pub"
	//	privFileN := "key.priv"
	//	if err := os.Remove(pubFileN); err != nil {
	//		t.Error("Could not remove public key")
	//	}
	//	if err := os.Remove(privFileN); err != nil {
	//		t.Error("Could not remove private key")
	//	}
	//})
	bitSize := 1024
	key, err := createRSAKey(bitSize)
	if err != nil || key.N.BitLen() != bitSize {
		log.Debug(err)
		t.Error("Error in createRSAKey")
		return
	}
}

func TestOpenKeys(t *testing.T) {
	pubPem, privPem, err := OpenKeys("../testdata/keypair1/")
	if pubPem == nil || privPem == nil || err != nil {
		log.Debug(err)
		t.Error("Error in OpenKeys")
		return
	}
}

func TestPemToKeys(t *testing.T) {
	pubPem, privPem, err := OpenKeys("../testdata/keypair1/")
	if pubPem == nil || privPem == nil || err != nil {
		log.Debug(err)
		t.Error("Error in OpenKeys")
		return
	}

	if privKey, err := PemToKeys(privPem); privKey == nil || err != nil {
		log.Debug(err)
		log.Error("Error in PemToKeys")
		return
	}
}

func TestPemToSha256(t *testing.T) {
	pubPem, privPem, err := OpenKeys("../testdata/keypair1/")
	if pubPem == nil || privPem == nil || err != nil {
		log.Debug(err)
		t.Error("Error in OpenKeys")
		return
	}
	PemToSha256(pubPem)
}

func TestGenAESKey(t *testing.T) {
	if key, err := genSymKey(); err != nil || len(key) != 32 {
		log.Debug(err)
		t.Error("Error in genAESKey")
		return
	}
}

func TestBytesToBase64(t *testing.T) {
	encoded := BytesToBase64(t, []byte("test string"))
	if !bytes.Equal(encoded, []byte("dGVzdCBzdHJpbmc=")) {
		t.Error("Error in BytesToBase64")
		return
	}
}

func TestKeyEncryptSignAESKey(t *testing.T) {
	// Open Key as PEM
	_, privPem, err := OpenKeys("../testdata/keypair1/")
	if err != nil {
		log.Debug(err)
		t.Error("Error in OpenKeys")
		return
	}

	// Convert PEM to key structs
	privKey, err := PemToKeys(privPem)
	if err != nil {
		log.Debug(err)
		t.Error("Error in PemToKeys")
		return
	}

	// Generate AES key
	key, err := genSymKey()
	if err != nil {
		log.Debug(err)
		t.Error("Error in genAESKey")
		return
	}

	log.Debug(fmt.Sprintf("Key(Hex): %x", key))
	log.Debug(fmt.Sprintf("Key(Sha256,Hex): %x", sha256.Sum256(key)))

	if _, _, err := EncryptSignMsg(key, &privKey.PublicKey, privKey); err != nil {
		log.Debug(err)
		t.Error("Error in keyExchange")
		return
	}
}

// BytesToBase64 encodes raw bytes to base64
func BytesToBase64(t *testing.T, data []byte) []byte {
	t.Helper()
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data[:])
	return encoded
}
