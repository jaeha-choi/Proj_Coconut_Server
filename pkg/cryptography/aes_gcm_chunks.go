package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"github.com/jaeha-choi/Proj_Coconut_Utility/common"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"github.com/jaeha-choi/Proj_Coconut_Utility/util"
	"io"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	// ChunkSize is a size of each file chunks in bytes.
	// Should be less than max value of uint32 (4294967295)
	// since the util package use unsigned 4 bytes to represent the data size.
	ChunkSize    = 16777216 // 2^24 bytes, about 16.7 MB
	UDPChunkSize = 4066
	IvSize       = 12
	SymKeySize   = 32

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
	readChunkNum  uint32
	writeOffset   uint64
	writeChunkNum uint32
	fileSize      uint64
	chunkCount    uint32
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
	chunkNum := math.Ceil(float64(fileSize) / UDPChunkSize)
	return &AesGcmChunk{
		key:           symKey,
		file:          srcFile,
		fileName:      fileName,
		readOffset:    0,
		readChunkNum:  0,
		writeOffset:   0,
		writeChunkNum: 0,
		fileSize:      uint64(fileSize),
		chunkCount:    uint32(chunkNum),
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
// TODO: Send error if previous operation was unsuccessful
func (ag *AesGcmChunk) Encrypt(writer io.Writer, receiverPubKey *rsa.PublicKey, senderPrivKey *rsa.PrivateKey) (err error) {
	var command = common.File

	// Encrypt and sign symmetric encryption key
	dataEncrypted, dataSignature, err := EncryptSignMsg(ag.key, receiverPubKey, senderPrivKey)
	if err != nil {
		log.Debug(err)
		log.Error("Error in EncryptSignMsg")
		return err
	}

	// Send encrypted symmetric key
	if _, err = util.WriteMessage(writer, dataEncrypted, nil, command); err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while sending dataEncrypted")
		return err
	}

	// Send encrypted symmetric key signature
	if _, err = util.WriteMessage(writer, dataSignature, nil, command); err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while sending dataSignature")
		return err
	}

	// Encrypt chunkCount + file name
	encryptedFileName, fileNameIv, err := ag.encryptBytes(append(util.Uint32ToByte(ag.chunkCount), []byte(ag.fileName)...))
	if err != nil {
		log.Debug(err)
		log.Error("Error in encryptBytes while encrypting file name")
		return err
	}
	// Send IV (Nonce)
	if _, err = util.WriteMessage(writer, fileNameIv, nil, command); err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while writing fileNameIv")
		return err
	}
	// Send encrypted file name
	if _, err = util.WriteMessage(writer, encryptedFileName, nil, command); err != nil {
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
		if _, err = util.WriteMessage(writer, iv, nil, command); err != nil {
			log.Debug(err)
			log.Error("Error in WriteBytes while sending iv")
			return err
		}
		// Send encrypted file chunk + current chunk number (first two bytes)
		if _, err = util.WriteMessage(writer, encryptedFileChunk, nil, command); err != nil {
			log.Debug(err)
			log.Error("Error in WriteBytes while sending encryptedFileChunk")
			return err
		}
	}

	// Close input file when done reading
	if err := ag.file.Close(); err != nil {
		log.Debug(err)
		return err
	}

	return nil
}

// EncryptUDP encrypts file and write to UDPConn and return error if raised.
// Receiver's public key is required for encrypting symmetric encryption key.
// Sender's private key is required for signing the encrypted key.
// err == nil indicates successful execution.
func (ag *AesGcmChunk) EncryptUDP(writer *net.UDPConn, address *net.UDPAddr, receiverPubKey *rsa.PublicKey, senderPrivKey *rsa.PrivateKey) (err error) {
	var command = common.File

	// Encrypt and sign symmetric encryption key
	dataEncrypted, dataSignature, err := EncryptSignMsg(ag.key, receiverPubKey, senderPrivKey)
	if err != nil {
		log.Debug(err)
		log.Error("Error in EncryptSignMsg")
		return err
	}

	// Send encrypted symmetric key
	if _, err = util.WriteMessageUDP(writer, address, dataEncrypted, nil, command); err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while sending dataEncrypted")
		return err
	}

	// Send encrypted symmetric key signature
	if _, err = util.WriteMessageUDP(writer, address, dataSignature, nil, command); err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while sending dataSignature")
		return err
	}

	// Encrypt chunkCount + file name
	encryptedFileName, fileNameIv, err := ag.encryptBytes(append(util.Uint32ToByte(ag.chunkCount), []byte(ag.fileName)...))
	if err != nil {
		log.Debug(err)
		log.Error("Error in encryptBytes while encrypting file name")
		return err
	}
	// Send IV (Nonce)
	if _, err = util.WriteMessageUDP(writer, address, fileNameIv, nil, command); err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while writing fileNameIv")
		return err
	}
	// Send encrypted file name
	if _, err = util.WriteMessageUDP(writer, address, encryptedFileName, nil, command); err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while writing encrypted file name")
		return err
	}

	// Send encrypted file
	var encryptedFileChunk, iv []byte
	// Loop until every byte is sent
	// ag.readOffset and ag.readChunkNum are updated in encryptChunk
	for ag.readOffset < ag.fileSize {
		time.Sleep(10 * time.Microsecond)
		if ag.readOffset+UDPChunkSize >= ag.fileSize {
			// Send last chunk
			encryptedFileChunk, iv, err = ag.encryptChunk(ag.fileSize - ag.readOffset)
		} else {
			// Send chunk
			encryptedFileChunk, iv, err = ag.encryptChunk(UDPChunkSize)
		}
		if err != nil {
			log.Debug(err)
			log.Error("Error in encryptChunk. Read Offset: ", int(ag.readOffset))
			return err
		}
		// Send IV in plain text
		if _, err = util.WriteMessageUDP(writer, address, iv, nil, command); err != nil {
			log.Debug(err)
			log.Error("Error in WriteBytes while sending iv")
			return err
		}
		// Send encrypted file chunk + current chunk number (first two bytes)
		if _, err = util.WriteMessageUDP(writer, address, encryptedFileChunk, nil, command); err != nil {
			log.Debug(err)
			log.Error("Error in WriteBytes while sending encryptedFileChunk")
			return err
		}
	}
	log.Debug(ag.chunkCount)
	// Close input file when done reading
	if err := ag.file.Close(); err != nil {
		log.Debug(err)
		return err
	}

	return nil
}

// EncryptFileUDP
/* Encrypt Reliable UDP Process:
** Must use encrypt setup first **
	Create symmetric key `EncryptSignMsg`
*	Send key	seq:0000
-		[ACK] Read key
* 	Send Signature	seq:0001
-		[ACK] Read Signature
	Encrypt num-chunks and filename
*	Send Filename IV (random number) seq:0002
- 		[ACK] Read filename IV
*	Send encrypted filename + chunk count seq:0003
- 		[ACK] Read filename
// begin encrypting and sending file chunks //
	while offset < size
		Encrypt next file chunk of size *chunksize  (variable)*
*		Send file chunk iv	+ seq. 	seq:0004 to nnnn-1 where nnnn is number of packets + 4 (init packets) (nnnn can range from $0004 - $fffe)
-	 		[ACK] Read file chunk iv seq
*		Send file chunk + seq
-			[ACK] Read file chunk seq
	Close file

// general ack (Encrypt) sequence
send(message)
err = read
if err
	for  i = 0; i  < 5; i++ // up to 5 timeouts
		send again
		err = read again
		if err == nil
			verify correct read
			break
// end general (Encrypt) ack sequence*/
func (ag *AesGcmChunk) EncryptFileUDP(writer *net.UDPConn, address *net.UDPAddr, receiverPubKey *rsa.PublicKey, senderPrivKey *rsa.PrivateKey) (err error) {
	var command = common.File
	// add 4 to chunk count for init key iv, and filename
	sequenceNum := uint32(0)
	// Encrypt and sign symmetric encryption key
	dataEncrypted, dataSignature, err := EncryptSignMsg(ag.key, receiverPubKey, senderPrivKey)
	if err != nil {
		log.Debug(err)
		log.Error("Error in EncryptSignMsg")
		return err
	}

	// Send encrypted symmetric key
	// seq: 0000
	packet, err := util.WriteFilePacketUDP(writer, address, sequenceNum, ag.chunkCount, nil, command, dataEncrypted)
	if err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while sending dataEncrypted")
		return err
	}
	if !util.ReadAckUDP(sequenceNum, writer, address, packet) {
		return common.TimeoutError
	}
	sequenceNum++
	// Send encrypted symmetric key signature
	// seq: 0001
	packet, err = util.WriteFilePacketUDP(writer, address, sequenceNum, ag.chunkCount, nil, command, dataSignature)
	if err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while sending dataEncrypted")
		return err
	}
	if !util.ReadAckUDP(sequenceNum, writer, address, packet) {
		return common.TimeoutError
	}
	sequenceNum++
	// Encrypt chunkCount + file name
	encryptedFileName, fileNameIv, err := ag.encryptBytes(append(util.Uint32ToByte(ag.chunkCount), []byte(ag.fileName)...))
	if err != nil {
		log.Debug(err)
		log.Error("Error in encryptBytes while encrypting file name")
		return err
	}
	// Send IV (Nonce)
	// seq: 0002
	packet, err = util.WriteFilePacketUDP(writer, address, sequenceNum, ag.chunkCount, nil, command, fileNameIv)
	if err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while sending dataEncrypted")
		return err
	}
	if !util.ReadAckUDP(sequenceNum, writer, address, packet) {
		return common.TimeoutError
	}
	sequenceNum++
	// Send encrypted file name
	// seq: 00003
	packet, err = util.WriteFilePacketUDP(writer, address, sequenceNum, ag.chunkCount, nil, command, encryptedFileName)
	if err != nil {
		log.Debug(err)
		log.Error("Error in WriteBytes while sending dataEncrypted")
		return err
	}
	if !util.ReadAckUDP(sequenceNum, writer, address, packet) {
		return common.TimeoutError
	}
	sequenceNum++

	// Send encrypted file
	var encryptedFileChunk, iv []byte
	// Loop until every byte is sent
	// ag.readOffset and ag.readChunkNum are updated in encryptChunk
	for ag.readOffset < ag.fileSize {
		time.Sleep(10 * time.Microsecond)
		if ag.readOffset+UDPChunkSize >= ag.fileSize {
			// Send last chunk
			encryptedFileChunk, iv, err = ag.encryptChunk(ag.fileSize - ag.readOffset)
		} else {
			// Send chunk
			encryptedFileChunk, iv, err = ag.encryptChunk(UDPChunkSize)
		}
		if err != nil {
			log.Debug(err)
			log.Error("Error in encryptChunk. Read Offset: ", int(ag.readOffset))
			return err
		}
		// Send IV in plain text
		packet, err = util.WriteFilePacketUDP(writer, address, sequenceNum, ag.chunkCount, nil, command, iv)
		if err != nil {
			log.Debug(err)
			log.Error("Error in WriteBytes while sending dataEncrypted")
			return err
		}
		if !util.ReadAckUDP(sequenceNum, writer, address, packet) {
			return common.TimeoutError
		}
		// Send encrypted file chunk + current chunk number (first two bytes)
		packet, err = util.WriteFilePacketUDP(writer, address, sequenceNum, ag.chunkCount, nil, command, encryptedFileChunk)
		if err != nil {
			log.Debug(err)
			log.Error("Error in WriteBytes while sending dataEncrypted")
			return err
		}
		if !util.ReadAckUDP(sequenceNum, writer, address, packet) {
			return common.TimeoutError
		}
		sequenceNum++
	}
	// Close input file when done reading
	if err := ag.file.Close(); err != nil {
		log.Debug(err)
		return err
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
	currChunkNum := util.Uint32ToByte(ag.readChunkNum)
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
func (ag *AesGcmChunk) Decrypt(chanMap chan *util.Message, senderPubKey *rsa.PublicKey, receiverPrivKey *rsa.PrivateKey) (err error) {
	// Reads encrypted symmetric encryption key
	dataEncrypted := <-chanMap
	if dataEncrypted.ErrorCode != 0 {
		log.Debug(err)
		log.Error("Error in ReadBytes while getting dataEncrypted")
		return common.ErrorCodes[dataEncrypted.ErrorCode]
	}
	// Reads signature for encrypted symmetric encryption key
	dataSignature := <-chanMap
	if dataSignature.ErrorCode != 0 {
		log.Debug(err)
		log.Error("Error in ReadBytes while getting dataEncrypted")
		return common.ErrorCodes[dataSignature.ErrorCode]
	}
	// Verify and decrypts symmetric encryption key
	ag.key, err = DecryptVerifyMsg(dataEncrypted.Data, dataSignature.Data, senderPubKey, receiverPrivKey)
	if err != nil {
		log.Debug(err)
		log.Error("Error in DecryptVerifyMsg")
		return err
	}

	// Get IV for decrypting file name
	ivFileName := <-chanMap
	if ivFileName.ErrorCode != 0 {
		log.Debug(err)
		log.Error("Error while reading iv for file name")
		return common.ErrorCodes[ivFileName.ErrorCode]
	}

	// Get encrypted chunkCount + file name
	encryptedFileName := <-chanMap
	if encryptedFileName.ErrorCode != 0 {
		log.Debug(err)
		log.Error("Error while reading encrypted file name")
		return common.ErrorCodes[encryptedFileName.ErrorCode]
	}

	// Decrypt chunkCount + file name with encrypted data and IV
	decryptedFileName, err := ag.decryptBytes(encryptedFileName.Data, ivFileName.Data)
	if err != nil {
		log.Debug(err)
		log.Error("Error while decrypting file name")
		return err
	}

	// Total chunk count is appended to file name
	ag.chunkCount = binary.BigEndian.Uint32(decryptedFileName[:4])
	// Update file name
	ag.fileName = string(decryptedFileName[4:])
	// Receive file and decrypt
	var encryptedFileChunk, iv *util.Message
	// Loop until every chunk is received
	// ag.writeOffset and ag.writeChunkNum are updated in decryptChunk
	for ag.writeChunkNum < ag.chunkCount {
		// Read IV in plain text
		if iv = <-chanMap; iv.ErrorCode != 0 {
			log.Debug(err)
			log.Error("Error in ReadBytes while reading iv")
			return common.ErrorCodes[iv.ErrorCode]
		}
		// Read encrypted file chunk + current chunk number (first two bytes)
		if encryptedFileChunk = <-chanMap; encryptedFileChunk.ErrorCode != 0 {
			log.Debug(err)
			log.Error("Error in ReadBytes while reading encryptedFileChunk")
			return common.ErrorCodes[encryptedFileChunk.ErrorCode]
		}
		// Decrypt file chunk + current chunk number (first two bytes)
		decryptedFileChunk, _, err := ag.decryptChunk(encryptedFileChunk.Data, iv.Data)
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
	// Close output file when done writing
	if err := ag.file.Close(); err != nil {
		log.Debug(err)
		// If rename was unsuccessful, remove temp file
		if err := os.Remove(ag.file.Name()); err != nil {
			log.Debug(err)
			log.Error("Error while removing temp file. Temp file at: ", ag.file.Name())
			return err
		}
		return err
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
func (ag *AesGcmChunk) decryptChunk(encryptedData []byte, iv []byte) (decryptedData []byte, currChunkNum uint32, err error) {
	// Decrypt data
	decryptedData, err = ag.decryptBytes(encryptedData, iv)
	if err != nil {
		log.Debug(err)
		log.Error("Error in decryptBytes")
		return nil, 0, err
	}

	// Convert chunk number bytes to uint16 (first two bytes)
	currChunkNum = binary.BigEndian.Uint32(decryptedData[:4])
	decryptedFileChunk := decryptedData[4:]

	// If chunk was received in incorrect order, raise error
	if ag.writeChunkNum != currChunkNum {
		log.Error("Encrypted chunk was received in the incorrect order")
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

// DecryptFileUDP :
/* Decrypt Reliable UDP Process:
// Must use decrypt setup first //
*	Read key seq:0000
- 		[ACK] Send key
*	Read signature seq:0001
- 		[ACK] Send Signature
	Decrypt signature
*	Read Filename IV seq:0002
- 		[ACK] Send filename IV
*	Read Encrypted filename seq:0003
- 		[ACK] Send filename
	Decrypt filename + chunk count (last 2 bytes)
	update ag.filename
	// begin reading and decrypting file chunks //
	while chunkNum < chunk count
*		Read chunk IV
- 			[ACK] Send chunk IV
*		Read chunk
- 			[ACK] Send Chunk
		Decrypt chunk using iv
		Write chunk to file
	Close file
	rename file to decrypted filename */
func (ag *AesGcmChunk) DecryptFileUDP(peerConn *net.UDPConn, peerAddr *net.UDPAddr, senderPubKey *rsa.PublicKey, receiverPrivKey *rsa.PrivateKey) (err error) {
	response := make([]byte, 4)
	// Create read buffer
	// Reads encrypted symmetric encryption key
	dataEncrypted, err := util.ReadFilePacketUDP(peerConn)
	if dataEncrypted.ErrorCode != 0 || err != nil {
		log.Debug(err)
		log.Error("Error in ReadBytes while getting dataEncrypted")
		return common.ErrorCodes[dataEncrypted.ErrorCode]
	}
	binary.BigEndian.PutUint32(response, dataEncrypted.Sequence)
	if _, err = peerConn.WriteTo(response, peerAddr); err != nil {
		return err
	}
	// Reads signature for encrypted symmetric encryption key
	dataSignature, err := util.ReadFilePacketUDP(peerConn)
	if dataSignature.ErrorCode != 0 || err != nil {
		log.Debug(err)
		log.Error("Error in ReadBytes while getting dataEncrypted")
		return common.ErrorCodes[dataSignature.ErrorCode]
	}
	binary.BigEndian.PutUint32(response, dataSignature.Sequence)
	if _, err = peerConn.WriteTo(response, peerAddr); err != nil {
		return err
	}
	// Verify and decrypts symmetric encryption key
	ag.key, err = DecryptVerifyMsg(dataEncrypted.Data, dataSignature.Data, senderPubKey, receiverPrivKey)
	if err != nil {
		log.Debug(err)
		log.Error("Error in DecryptVerifyMsg")
		return err
	}

	// Get IV for decrypting file name
	ivFileName, err := util.ReadFilePacketUDP(peerConn)
	if ivFileName.ErrorCode != 0 || err != nil {
		log.Debug(err)
		log.Error("Error while reading iv for file name")
		return common.ErrorCodes[ivFileName.ErrorCode]
	}
	binary.BigEndian.PutUint32(response, ivFileName.Sequence)
	if _, err = peerConn.WriteTo(response, peerAddr); err != nil {
		return err
	}

	// Get encrypted chunkCount + file name
	encryptedFileName, err := util.ReadFilePacketUDP(peerConn)
	if encryptedFileName.ErrorCode != 0 || err != nil {
		log.Debug(err)
		log.Error("Error while reading encrypted file name")
		return common.ErrorCodes[encryptedFileName.ErrorCode]
	}
	binary.BigEndian.PutUint32(response, encryptedFileName.Sequence)
	if _, err = peerConn.WriteTo(response, peerAddr); err != nil {
		return err
	}

	// Decrypt chunkCount + file name with encrypted data and IV
	decryptedFileName, err := ag.decryptBytes(encryptedFileName.Data, ivFileName.Data)
	if err != nil {
		log.Debug(err)
		log.Error("Error while decrypting file name")
		return err
	}

	// Total chunk count is appended to file name
	ag.chunkCount = binary.BigEndian.Uint32(decryptedFileName[:4])
	// Update file name
	ag.fileName = string(decryptedFileName[4:])

	// Receive file and decrypt
	var encryptedFileChunk, iv *util.UDPMessage
	// Loop until every chunk is received
	// ag.writeOffset and ag.writeChunkNum are updated in decryptChunk
	for ag.writeChunkNum < ag.chunkCount {
		// Read IV in plain text
		if err = peerConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		if iv, err = util.ReadFilePacketUDP(peerConn); iv.ErrorCode != 0 || err != nil {
			log.Debug(err)
			log.Error("Error in ReadBytes while reading iv")
			return common.ErrorCodes[iv.ErrorCode]
		}
		binary.BigEndian.PutUint32(response, iv.Sequence)
		if _, err = peerConn.WriteTo(response, peerAddr); err != nil {
			return err
		}

		// Read encrypted file chunk + current chunk number (first two bytes)
		if encryptedFileChunk, err = util.ReadFilePacketUDP(peerConn); encryptedFileChunk.ErrorCode != 0 || err != nil {
			log.Debug(err)
			log.Error("Error in ReadBytes while reading encryptedFileChunk")
			return common.ErrorCodes[encryptedFileChunk.ErrorCode]
		}
		binary.BigEndian.PutUint32(response, encryptedFileChunk.Sequence)
		if _, err = peerConn.WriteTo(response, peerAddr); err != nil {
			return err
		}
		// Decrypt file chunk + current chunk number (first two bytes)
		decryptedFileChunk, _, err := ag.decryptChunk(encryptedFileChunk.Data, iv.Data)
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
	//*--------------------DO NOT CHANGE BELOW THIS LINE------------------------------*//
	// Close output file when done writing
	if err := ag.file.Close(); err != nil {
		log.Debug(err)
		// If rename was unsuccessful, remove temp file
		if err := os.Remove(ag.file.Name()); err != nil {
			log.Debug(err)
			log.Error("Error while removing temp file. Temp file at: ", ag.file.Name())
			return err
		}
		return err
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

// genSymKey generates random key for symmetric encryption
func genSymKey() (key []byte, err error) {
	// Since we're using AES, generate 32 bytes key for AES256
	key = make([]byte, SymKeySize)
	// Create random key for symmetric encryption
	if _, err := rand.Read(key); err != nil {
		log.Debug(err)
		log.Error("Error while generating symmetric encryption key")
		return nil, err
	}
	return key, nil
}
