package cryptography

import (
	"crypto/sha1"
	"fmt"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"github.com/jaeha-choi/Proj_Coconut_Utility/util"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
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

	privKey, err := OpenPrivKey("../testdata/keypairCat/", "cat.priv")
	if err != nil {
		log.Debug(err)
		t.Error("Error in OpenPrivKey")
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
	privKey1, err := OpenPrivKey("../testdata/keypairCat/", "cat.priv")
	if err != nil {
		log.Debug(err)
		t.Error("Error in OpenPrivKey")
		return
	}

	// Client 2
	privKey2, err := OpenPrivKey("../testdata/keypairFox/", "fox.priv")
	if err != nil {
		log.Debug(err)
		t.Error("Error in OpenPrivKey")
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

func TestAesGcmChunk_EncryptFileUDP(t *testing.T) {
	testPath := "/home/duncan/projects/Proj_Coconut_Utility/testdata"

	// // Setup udp address and connection
	addr := "127.0.0.1:12345"
	address, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Error(err)
	}
	UDPConn, err := net.ListenUDP("udp", address)
	if err != nil {
		t.Error(err)
	}
	addr2 := "127.0.0.1:54321"
	address2, err := net.ResolveUDPAddr("udp", addr2)
	if err != nil {
		t.Error(err)
	}
	UDPConn2, err := net.ListenUDP("udp", address2)
	if err != nil {
		t.Error(err)
	}
	// // Setup keys
	// cat : receiver
	// fox : sender
	recvPub, err := OpenPubKey(testPath+"/keypairCat", "cat.pub")
	if err != nil {
		t.Error(err)
		return
	}
	recvPriv, err := OpenPrivKey(testPath+"/keypairCat", "cat.priv")
	if err != nil {
		t.Error(err)
		return
	}
	sendPub, err := OpenPubKey(testPath+"/keypairFox", "fox.pub")
	if err != nil {
		t.Error(err)
		return
	}
	sendPriv, err := OpenPrivKey(testPath+"/keypairFox", "fox.priv")
	if err != nil {
		t.Error(err)
		return
	}
	//msgs := make(chan *util.Message)
	//go func() {
	//	for {
	//		buffer := make([]byte, 4096)
	//		msg, _, _ := util.ReadMessageUDP(UDPConn2, buffer)
	//		msgs <- msg
	//	}
	//}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		// // Setup encryption structure
		ag, err := EncryptSetup(testPath + "/A17_FlightPlan.pdf")
		log.Debug(ag.chunkCount)
		// Encrypt and send file
		err = ag.EncryptFileUDP(UDPConn, address2, recvPub, sendPriv)
		if err != nil {
			t.Error(err)
			return
		}
		log.Debug("file sent")
		wg.Done()
	}()
	//time.Sleep(1 * time.Second)
	wg.Add(1)
	go func() {
		// // Setup encryption structure
		ag, err := DecryptSetup()

		// Receive and decrypt file
		err = ag.DecryptFileUDP(UDPConn2, address, sendPub, recvPriv)
		if err != nil {
			t.Error(err)
			return
		}
		log.Debug("file decrypted")
		wg.Done()
	}()
	wg.Wait()
}

func TestEncryptSize(t *testing.T) {
	testPath := "/home/duncan/projects/Proj_Coconut_Utility/testdata"

	// // Setup udp address and connection
	addr := "127.0.0.1:12345"
	address, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Error(err)
	}
	UDPConn, err := net.ListenUDP("udp", address)
	if err != nil {
		t.Error(err)
	}
	addr2 := "127.0.0.1:54321"
	address2, err := net.ResolveUDPAddr("udp", addr2)
	if err != nil {
		t.Error(err)
	}
	//UDPConn2, err := net.ListenUDP("udp", address2)
	//if err != nil {
	//	t.Error(err)
	//}
	// // Setup keys
	// cat : receiver
	// fox : sender
	recvPub, err := OpenPubKey(testPath+"/keypairCat", "cat.pub")
	if err != nil {
		t.Error(err)
		return
	}
	//recvPriv, err := OpenPrivKey(testPath+"/keypairCat", "cat.priv")
	//if err != nil {
	//	t.Error(err)
	//	return
	//}
	//sendPub, err := OpenPubKey(testPath+"/keypairFox", "fox.pub")
	//if err != nil {
	//	t.Error(err)
	//	return
	//}
	sendPriv, err := OpenPrivKey(testPath+"/keypairFox", "fox.priv")
	if err != nil {
		t.Error(err)
		return
	}
	ag, err := EncryptSetup(testPath + "/cat.jpg")
	log.Debug(ag.fileSize)
	log.Debug(ag.chunkCount)
	if err != nil {
		t.Error()
	}
	err = ag.EncryptUDP(UDPConn, address2, recvPub, sendPriv)
	if err != nil {
		return
	}
}
