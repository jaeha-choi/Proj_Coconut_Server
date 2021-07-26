package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"github.com/jaeha-choi/Proj_Coconut_Utility/util"
	"io"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
)

const (
	// ChunkSize is a size of each file chunks in bytes.
	// Should be less than max value of uint32 (4294967295)
	// since the util package use unsigned 4 bytes to represent the data size.
	ChunkSize = 16777216 // 2^24 bytes, about 16.7 MB
	IvSize    = 12

	// MaxFileSize indicates theoretical limit for the file size. Because chunk number are
	// indicated with uint16, MaxFileSize depends on ChunkSize. However, actual file limit
	// may depend on the IV, file system, OS, etc.
	//MaxFileSize = ChunkSize * 65535
	//gcmOverhead = 16
)

// ChunkIncorrectOrder occurs when encrypted file chunks are received in incorrect order.
var ChunkIncorrectOrder = errors.New("encrypted chunk incorrect order")

// IncompleteFile occurs when written chunk size != total chunk size.
var IncompleteFile = errors.New("incomplete file")

// AesGcmChunk stores data for encrypting or decrypting chunks, but it cannot be both.
type AesGcmChunk struct {
	key           []byte
	file          *os.File
	fileName      string
	readOffset    uint64
	readChunkNum  uint16
	writeOffset   uint64
	writeChunkNum uint16
	fileSize      uint64
	chunkCount    uint16
}

// EncryptSetup opens file, determine number of chunks, then return *AesGcmChunk
func EncryptSetup(fileN string) (ag *AesGcmChunk, err error) {
	// Generate symmetric encryption key
	symKey, err := genSymKey()
	if err != nil {
		log.Debug(err)
		log.Error("Error while generating an AES key")
		return nil, err
	}
	// Open src file for encryption
	srcFile, err := os.Open(fileN)
	if err != nil {
		log.Debug(err)
		log.Error("Error while opening a file")
		return nil, err
	}
	// Get size of the src file
	fileStat, err := os.Stat(fileN)
	if err != nil {
		log.Debug(err)
		log.Error("Error while getting stats")
		return nil, err
	}
	// Split path from file name so dst file can use this file name
	_, fileName := filepath.Split(fileN)
	// Get file size
	fileSize := fileStat.Size()
	// Get number of chunks
	chunkNum := math.Ceil(float64(fileSize) / ChunkSize)
	return &AesGcmChunk{
		key:           symKey,
		file:          srcFile,
		fileName:      fileName,
		readOffset:    0,
		readChunkNum:  0,
		writeOffset:   0,
		writeChunkNum: 0,
		fileSize:      uint64(fileSize),
		chunkCount:    uint16(chunkNum),
	}, nil
}

// DecryptSetup creates temporary file, make directory if it doesn't exist then return *AesGcmChunk
func DecryptSetup() (ag *AesGcmChunk, err error) {
	// Create directory if it doesn't exist
	if err = os.MkdirAll(util.DownloadPath, os.ModePerm); err != nil {
		log.Debug(err)
		log.Error("Error while creating download directory")
		return nil, err
	}
	// Create file for decrypted data
	tmpFile, err := ioutil.TempFile(util.DownloadPath, ".tmp_decrypted_")
	if err != nil {
		log.Debug(err)
		log.Error("Temp file could not be created")
		return nil, err
	}
	return &AesGcmChunk{
		key:           nil,
		file:          tmpFile,
		fileName:      "",
		readOffset:    0,
		readChunkNum:  0,
		writeOffset:   0,
		writeChunkNum: 0,
		fileSize:      0,
		chunkCount:    0,
	}, nil
}

// Encrypt encrypts file and write to writer and return error if raised.
// Receiver's public key is required for encrypting symmetric encryption key.
// Sender's private key is required for signing the encrypted key.
// err == nil indicates successful execution.
func (ag *AesGcmChunk) Encrypt(writer io.Writer, receiverPubKey *rsa.PublicKey, senderPrivKey *rsa.PrivateKey) (err error) {
	keyChNum := append(ag.key, util.Uint16ToByte(ag.chunkCount)...)
	// Encrypt and sign symmetric encryption key
	dataEncrypted, dataSignature, err := EncryptSignMsg(keyChNum, receiverPubKey, senderPrivKey)
	if err != nil {
		log.Debug(err)
		log.Error("Error in EncryptSignMsg")
		return err
	}

	// Send encrypted symmetric key
	if _, err = util.WriteBytes(writer, dataEncrypted); err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while sending dataEncrypted")
		return err
	}

	// Send encrypted symmetric key signature
	if _, err = util.WriteBytes(writer, dataSignature); err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while sending dataSignature")
		return err
	}

	// Encrypt file name
	encryptedFileName, fileNameIv, err := ag.encryptBytes([]byte(ag.fileName))
	if err != nil {
		log.Debug(err)
		log.Error("Error in encryptBytes while encrypting file name")
		return err
	}
	// Send IV (Nonce)
	if _, err = util.WriteBytes(writer, fileNameIv); err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while writing fileNameIv")
		return err
	}
	// Send encrypted file name
	if _, err = util.WriteBytes(writer, encryptedFileName); err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while writing encrypted file name")
		return err
	}

	// Send encrypted file
	var encryptedFileChunk, iv []byte
	// Loop until every byte is sent
	// ag.readOffset and ag.readChunkNum are updated in encryptChunk
	for ag.readOffset < ag.fileSize {
		if ag.readOffset+ChunkSize >= ag.fileSize {
			// Send last chunk
			encryptedFileChunk, iv, err = ag.encryptChunk(ag.fileSize - ag.readOffset)
		} else {
			// Send chunk
			encryptedFileChunk, iv, err = ag.encryptChunk(ChunkSize)
		}
		if err != nil {
			log.Debug(err)
			log.Error("Error in encryptChunk. Read Offset: ", int(ag.readOffset))
			return err
		}
		// Send IV in plain text
		if _, err = util.WriteBytes(writer, iv); err != nil {
			log.Debug(err)
			log.Error("Error in WriteBytes while sending iv")
			return err
		}
		// Send encrypted file chunk + current chunk number (first two bytes)
		if _, err = util.WriteBytes(writer, encryptedFileChunk); err != nil {
			log.Debug(err)
			log.Error("Error in WriteBytes while sending encryptedFileChunk")
			return err
		}
	}
	return nil
}

// encryptChunk encrypts portion of the file and return it as []byte with current chunk number
// appended in the beginning (first two bytes). IV is also returned in plain text.
// err == nil indicates successful execution.
func (ag *AesGcmChunk) encryptChunk(chunkSize uint64) (encryptedData []byte, iv []byte, err error) {
	// Read chunk of file to encrypt
	plain := make([]byte, int(chunkSize))
	//plain := make([]byte, int(chunkSize)-gcmOverhead-len(currChunkNum))
	if _, err := io.ReadFull(ag.file, plain); err != nil {
		log.Debug(err)
		log.Error("Error while reading src file")
		return nil, nil, err
	}

	// Get current chunk number
	currChunkNum := util.Uint16ToByte(ag.readChunkNum)
	// Plain data is combined with current chunk number to be sent
	plain = append(currChunkNum, plain...)

	// Encrypt chunk of file and return encrypted output, IV, and error, if any.
	if encryptedData, iv, err = ag.encryptBytes(plain); err != nil {
		log.Debug(err)
		log.Error("Error in encryptBytes")
		return nil, nil, err
	}

	// Update variables for loop in Encrypt
	ag.readChunkNum += 1
	ag.readOffset += uint64(len(plain) - len(currChunkNum))

	return encryptedData, iv, err
}

// encryptBytes encrypts plain and return encrypted data, IV that was used, and error, if any.
// err == nil indicates successful execution.
func (ag *AesGcmChunk) encryptBytes(plain []byte) (encryptedData []byte, iv []byte, err error) {
	block, err := aes.NewCipher(ag.key)
	if err != nil {
		log.Debug(err)
		log.Error("Error while creating new cipher block")
		return nil, nil, err
	}
	// Generate random IV.
	// To save some bandwidth, some portion of the IV can be static (e.g. 32 bits)
	// while the rest (e.g. 64 bits) remains dynamic.
	iv = make([]byte, IvSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Debug(err)
		log.Error("Error while creating iv")
		return nil, nil, err
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Debug(err)
		log.Error("Error in NewGCM")
		return nil, iv, err
	}
	// Get encrypted data
	encryptedData = aesGcm.Seal(nil, iv, plain, nil)
	return encryptedData, iv, nil
}

// Decrypt reads encrypted data from reader and decrypts the file and return error, if raised.
// Sender's public key is required for verifying signature.
// Receiver's private key is required for decrypting symmetric encryption key.
// err == nil indicates successful execution.
func (ag *AesGcmChunk) Decrypt(reader io.Reader, senderPubKey *rsa.PublicKey, receiverPrivKey *rsa.PrivateKey) (err error) {
	// Reads encrypted symmetric encryption key
	dataEncrypted, err := util.ReadBytes(reader)
	if err != nil {
		log.Debug(err)
		log.Error("Error in ReadBytes while getting dataEncrypted")
		return err
	}
	// Reads signature for encrypted symmetric encryption key
	dataSignature, err := util.ReadBytes(reader)
	if err != nil {
		log.Debug(err)
		log.Error("Error in ReadBytes while getting dataEncrypted")
		return err
	}
	// Verify and decrypts symmetric encryption key
	dataPlain, err := DecryptVerifyMsg(dataEncrypted, dataSignature, senderPubKey, receiverPrivKey)
	if err != nil {
		log.Debug(err)
		log.Error("Error in DecryptVerifyMsg")
		return err
	}

	ag.key = dataPlain[:SymKeySize]
	// Total chunk count is appended to symmetric encryption key
	ag.chunkCount = util.ByteToUint16(dataPlain[SymKeySize:])

	// Get IV for decrypting file name
	ivFileName, err := util.ReadBytes(reader)
	if err != nil {
		log.Debug(err)
		log.Error("Error while reading iv for file name")
		return err
	}

	// Get encrypted file name
	encryptedFileName, err := util.ReadBytes(reader)
	if err != nil {
		log.Debug(err)
		log.Error("Error while reading encrypted file name")
		return err
	}

	// Decrypt file name with encrypted data and IV
	decryptedFileName, err := ag.decryptBytes(encryptedFileName, ivFileName)
	if err != nil {
		log.Debug(err)
		log.Error("Error while decrypting file name")
		return err
	}

	// Update file name
	ag.fileName = string(decryptedFileName)

	// Receive file and decrypt
	var encryptedFileChunk, iv []byte
	// Loop until every chunk is received
	// ag.writeOffset and ag.writeChunkNum are updated in decryptChunk
	for ag.writeChunkNum < ag.chunkCount {
		// Read IV in plain text
		if iv, err = util.ReadBytes(reader); err != nil {
			log.Debug(err)
			log.Error("Error in ReadBytes while reading iv")
			return err
		}
		// Read encrypted file chunk + current chunk number (first two bytes)
		if encryptedFileChunk, err = util.ReadBytes(reader); err != nil {
			log.Debug(err)
			log.Error("Error in ReadBytes while reading encryptedFileChunk")
			return err
		}
		// Decrypt file chunk + current chunk number (first two bytes)
		decryptedFileChunk, _, err := ag.decryptChunk(encryptedFileChunk, iv)
		if err != nil {
			log.Debug(err)
			log.Error("Error in decryptChunk")
			return err
		}
		// Write decrypted data to temp file
		if _, err = ag.file.Write(decryptedFileChunk); err != nil {
			log.Debug(err)
			log.Error("Error while writing decrypted file chunk to temp file")
			return err
		}
	}
	// If file was fully processed, rename temp file to actual name
	if ag.writeChunkNum == ag.chunkCount {
		// Rename temporary file
		if err := os.Rename(ag.file.Name(), filepath.Join(util.DownloadPath, ag.fileName)); err != nil {
			log.Debug(err)
			log.Debug("Tmp file name: ", ag.file.Name())
			log.Debug("File name: ", ag.fileName)
			log.Error("Error moving the temp file to download path")
			// If rename was unsuccessful, remove temp file
			if err := os.Remove(ag.file.Name()); err != nil {
				log.Debug(err)
				log.Error("Error while removing temp file. Temp file at: ", ag.file.Name())
				return err
			}
			return err
		}
	} else {
		log.Error("Not all chunks were received")
		// If file was not fully processed, delete file
		if err := os.Remove(ag.file.Name()); err != nil {
			log.Debug(err)
			log.Error("Error while removing temp file. Temp file at: ", ag.file.Name())
			return err
		}
		return IncompleteFile
	}

	return nil
}

// decryptChunk decrypts encryptedData with IV and current chunk number.
// Decrypted data and current chunk number is returned with error, if any.
// err == nil indicates successful execution.
func (ag *AesGcmChunk) decryptChunk(encryptedData []byte, iv []byte) (decryptedData []byte, currChunkNum uint16, err error) {
	// Decrypt data
	decryptedData, err = ag.decryptBytes(encryptedData, iv)
	if err != nil {
		log.Debug(err)
		log.Error("Error in decryptBytes")
		return nil, 0, err
	}

	// Convert chunk number bytes to uint16 (first two bytes)
	currChunkNum = util.ByteToUint16(decryptedData[:2])
	decryptedFileChunk := decryptedData[2:]

	// If chunk was received in incorrect order, raise error
	if ag.writeChunkNum != currChunkNum {
		log.Error("Encrypted chunk was received in an incorrect order")
		return decryptedFileChunk, currChunkNum, ChunkIncorrectOrder
	}

	// Update variables for loop in Decrypt
	ag.writeChunkNum += 1
	ag.writeOffset += uint64(len(decryptedFileChunk))

	return decryptedFileChunk, currChunkNum, nil
}

// decryptBytes decrypts encryptedData with IV. Decrypted data and error is returned, if any.
// err == nil indicates successful execution.
func (ag *AesGcmChunk) decryptBytes(encryptedData []byte, iv []byte) (decryptedData []byte, err error) {
	block, err := aes.NewCipher(ag.key)
	if err != nil {
		log.Debug(err)
		log.Error("Error while creating new cipher block")
		return nil, err
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Debug(err)
		log.Error("Error in NewGCM")
		return nil, err
	}
	// Decrypt the encryptedData
	if decryptedData, err = aesGcm.Open(nil, iv, encryptedData, nil); err != nil {
		log.Debug(err)
		log.Error("Error in Open in decryptChunk")
		return nil, err
	}
	return decryptedData, nil
}

// Close closes working file
func (ag *AesGcmChunk) Close() (err error) {
	return ag.file.Close()
}
