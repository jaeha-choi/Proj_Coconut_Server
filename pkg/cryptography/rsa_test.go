package cryptography

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"github.com/jaeha-choi/Proj_Coconut_Utility/util"
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
	pem, err := OpenKeysAsBlock("../testdata/keypairCat/", "cat.pub")
	if pem == nil || err != nil {
		log.Debug(err)
		t.Error("Error in OpenKeysAsBlock")
		return
	}
	pem, err = OpenKeysAsBlock("../testdata/keypairCat/", "cat.priv")
	if pem == nil || err != nil {
		log.Debug(err)
		t.Error("Error in OpenKeysAsBlock")
		return
	}
}

func TestPemToSha256(t *testing.T) {
	pem, err := OpenKeysAsBlock("../testdata/keypairCat/", "cat.pub")
	if pem == nil || err != nil {
		log.Debug(err)
		t.Error("Error in OpenKeysAsBlock")
		return
	}
	PemToSha256(pem)
}

func TestGenAESKey(t *testing.T) {
	if key, err := genSymKey(); err != nil || len(key) != 32 {
		log.Debug(err)
		t.Error("Error in genAESKey")
		return
	}
}

func TestBytesToBase64(t *testing.T) {
	encoded := util.BytesToBase64([]byte("test string"))
	if !bytes.Equal(encoded, []byte("dGVzdCBzdHJpbmc=")) {
		t.Error("Error in BytesToBase64")
		return
	}
}

func TestKeyEncryptSignAESKey(t *testing.T) {
	// Open Key
	privKey, err := OpenPrivKey("../testdata/keypairCat/", "cat.priv")
	if err != nil {
		log.Debug(err)
		t.Error("Error in OpenPrivKey")
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

func TestKeyEncryptDecryptAESKey(t *testing.T) {

	// Client Cat
	// Open Key
	privKey1, err := OpenPrivKey("../testdata/keypairCat/", "cat.priv")
	if err != nil {
		log.Debug(err)
		t.Error("Error in OpenPrivKey")
		return
	}

	// Client Fox
	// Open Key
	privKey3, err := OpenPrivKey("../testdata/keypairFox/", "Fox.priv")
	if err != nil {
		log.Debug(err)
		t.Error("Error in OpenPrivKey")
		return
	}

	// Generate AES key
	rawKey, err := genSymKey()
	if err != nil {
		log.Debug(err)
		t.Error("Error in genAESKey")
		return
	}

	data, sig, err := EncryptSignMsg(rawKey, &privKey3.PublicKey, privKey1)
	if err != nil {
		log.Debug(err)
		t.Error("Error in keyExchange")
		return
	}

	key, err := DecryptVerifyMsg(data, sig, &privKey1.PublicKey, privKey3)
	if err != nil {
		log.Debug(err)
		t.Error("Error in keyExchange")
		return
	}
	log.Debug(fmt.Sprintf("Raw Key(Hex): \t\t\t%x", rawKey))
	log.Debug(fmt.Sprintf("Decrypted Key(Hex): \t%x", key))
	log.Debug(fmt.Sprintf("Raw Key(Sha256,Hex): \t\t%x", sha256.Sum256(rawKey)))
	log.Debug(fmt.Sprintf("Decrypted Key(Sha256,Hex): \t%x", sha256.Sum256(key)))

	if bytes.Compare(rawKey, key) != 0 {
		t.Error("Key mismatch")
	}

}

//
//func TestOpenPubKey(t *testing.T) {
//	key , _:= OpenPubKey("./", "key.pub")
//	log.Debug(key.E)
//	log.Debug(key.N.Bytes())
//}

// BytesToBase64 encodes raw bytes to base64
func BytesToBase64(t *testing.T, data []byte) []byte {
	t.Helper()
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data[:])
	return encoded
}
