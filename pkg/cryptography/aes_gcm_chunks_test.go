package cryptography

import (
	"crypto/sha1"
	"fmt"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"github.com/jaeha-choi/Proj_Coconut_Utility/util"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	defer func() {
		if err := os.RemoveAll(util.DownloadPath); err != nil {
			log.Debug(err)
			log.Error("Existing directory not deleted, perhaps it does not exist?")
		}
	}()
	testFileN := "../testdata/checksum.txt"
	_, privPem, err := OpenKeys("../testdata/keypair1/")
	if err != nil {
		log.Debug(err)
		t.Error("Error in OpenKeys")
		return
	}
	privKey, err := PemToKeys(privPem)
	if err != nil {
		log.Debug(err)
		t.Error("Error in PemToKeys")
		return
	}

	tmpFile, err := os.Create("testTmp")
	if err != nil {
		log.Debug(err)
		t.Error("Error opening temp file")
		return
	}
	defer func() {
		if err := tmpFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Error closing tmp file")
			return
		}
		if err := os.Remove(tmpFile.Name()); err != nil {
			log.Debug(err)
			t.Error("Error while removing temp file. Temp file at: ", tmpFile.Name())
			return
		}
	}()

	// Encrypt
	streamEncrypt, err := EncryptSetup(testFileN)
	if err != nil {
		log.Debug(err)
		t.Error("Error in EncryptSetup")
		return
	}
	err = streamEncrypt.Encrypt(tmpFile, &privKey.PublicKey, privKey)
	if err != nil {
		log.Debug(err)
		t.Error("Error in Encrypt")
		return
	}

	// Reset offset
	if _, err := tmpFile.Seek(0, 0); err != nil {
		log.Debug(err)
		t.Error("Error resetting offset")
		return
	}

	// Decrypt
	streamDecrypt, err := DecryptSetup()
	if err != nil {
		log.Debug(err)
		t.Error("Error in DecryptSetup")
		return
	}

	fileChan := make(chan *util.Message, 100)
	for {
		msg, err := util.ReadMessage(tmpFile)
		if err == io.EOF {
			break
		}
		fileChan <- msg
	}

	err = streamDecrypt.Decrypt(fileChan, &privKey.PublicKey, privKey)
	if err != nil {
		log.Debug(err)
		t.Error("Error in Decrypt")
		return
	}
}

func TestEncryptDecrypt2(t *testing.T) {
	defer func() {
		if err := os.RemoveAll(util.DownloadPath); err != nil {
			log.Debug(err)
			log.Error("Existing directory not deleted, perhaps it does not exist?")
		}
	}()
	testFileN := "../testdata/cat.jpg"

	tmpFile, err := os.Create("testTmp")
	if err != nil {
		log.Debug(err)
		t.Error("Error opening temp file")
		return
	}
	defer func() {
		if err := tmpFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Error closing tmp file")
			return
		}
		if err := os.Remove(tmpFile.Name()); err != nil {
			log.Debug(err)
			t.Error("Error while removing temp file. Temp file at: ", tmpFile.Name())
			return
		}
	}()

	// Client 1
	_, privPem1, err := OpenKeys("../testdata/keypair1")
	if err != nil {
		log.Debug(err)
		t.Error("Error in OpenKeys")
		return
	}
	privKey1, err := PemToKeys(privPem1)
	if err != nil {
		log.Debug(err)
		t.Error("Error in PemToKeys")
		return
	}

	// Client 2
	_, privPem2, err := OpenKeys("../testdata/keypair2")
	if err != nil {
		log.Debug(err)
		t.Error("Error in OpenKeys")
		return
	}
	privKey2, err := PemToKeys(privPem2)
	if err != nil {
		log.Debug(err)
		t.Error("Error in PemToKeys")
		return
	}

	// Encrypt
	streamEncrypt, err := EncryptSetup(testFileN)
	if err != nil {
		log.Debug(err)
		t.Error("Error in EncryptSetup")
		return
	}

	err = streamEncrypt.Encrypt(tmpFile, &privKey2.PublicKey, privKey1)
	if err != nil {
		log.Debug(err)
		t.Error("Error in Encrypt")
		return
	}

	// Reset offset
	if _, err := tmpFile.Seek(0, 0); err != nil {
		log.Debug(err)
		t.Error("Error resetting offset")
		return
	}

	// Decrypt
	streamDecrypt, err := DecryptSetup()
	if err != nil {
		log.Debug(err)
		t.Error("Error in DecryptSetup")
		return
	}

	fileChan := make(chan *util.Message, 100)
	for {
		msg, err := util.ReadMessage(tmpFile)
		if err == io.EOF {
			break
		}
		fileChan <- msg
	}

	err = streamDecrypt.Decrypt(fileChan, &privKey1.PublicKey, privKey2)
	if err != nil {
		log.Debug(err)
		t.Error("Error in Decrypt")
		return
	}

	srcFile, err := os.Open(testFileN)
	if err != nil {
		log.Debug(err)
		t.Error("Error while opening src file for checksum comparison")
		return
	}
	defer func() {
		if err := srcFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Src file not closed")
			return
		}
	}()
	dstFile, err := os.Open(filepath.Join(util.DownloadPath, "cat.jpg"))
	if err != nil {
		log.Debug(err)
		t.Error("Error while opening src file for checksum comparison")
		return
	}
	defer func() {
		if err := dstFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Dst file not closed")
			return
		}
	}()
	if !ChecksumMatch(t, srcFile, dstFile) {
		t.Error("Checksum does not match")
	}
}

func ChecksumMatch(t *testing.T, expected io.Reader, result io.Reader) bool {
	t.Helper()

	// Get sha-1 sum of original
	h := sha1.New()
	if _, err := io.Copy(h, expected); err != nil {
		log.Debug(err)
		t.Error("Error while getting sha1sum for 'expected' reader")
		return false
	}
	f1Hash := fmt.Sprintf("%x", h.Sum(nil))
	log.Info("Expected sha1sum: ", f1Hash)

	// Get sha-1 sum of result
	h2 := sha1.New()
	if _, err := io.Copy(h2, result); err != nil {
		log.Debug(err)
		t.Error("Error while getting sha1sum for 'result' reader")
		return false
	}
	f2Hash := fmt.Sprintf("%x", h2.Sum(nil))
	log.Info("Resulted sha1sum: ", f2Hash)

	if f1Hash != f2Hash {
		return false
	}
	return true
}
