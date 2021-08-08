package util

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/jaeha-choi/Proj_Coconut_Utility/common"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
)

const (
	BufferSize   = 4096
	Uint32Max    = 4294967295
	DownloadPath = "./downloaded"
)

var EmptyFileName = errors.New("empty filename")

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, BufferSize)
		return b
	},
}

// ReadString reads string from a connection
func ReadString(reader io.Reader) (str string, err error) {
	bytes, err := ReadBytes(reader)
	return string(bytes), err
}

func ReadBytes(reader io.Reader) (b []byte, err error) {
	b, errCode, err := ReadBytesErr(reader)
	if err != nil {
		return b, err
	}
	// Next four lines CANNOT be replaced with "return b, errCode"
	// This is because errCode nil and nil are different types.
	if errCode != nil {
		return b, errCode
	}
	return b, nil
}

// ReadBytesErr reads b from reader.
// Returns error, if any.
func ReadBytesErr(reader io.Reader) (b []byte, errorCode *common.Error, err error) {
	// Read packet size
	size, err := readSize(reader)
	if err != nil {
		log.Debug(err)
		log.Error("Error while reading packet size")
		return nil, nil, err
	}

	//// ReadBytes always expect the size to be <= BufferSize
	//if size > BufferSize {
	//	log.Error("Size cannot be greater than ", BufferSize, ". Received size: ", size)
	//	return nil, SizeError
	//}

	// Read Error Code
	readError, err := readErrorCode(reader)
	if err != nil {
		log.Debug(err)
		log.Error("Error while reading error code")
		return nil, nil, err
	}

	// Read bytes from reader
	if b, err = readNBytes(reader, size); err != nil {
		log.Debug(err)
		log.Error("Error raised by readNBytes")
		return nil, readError, err
	}
	return b, readError, nil
}

// ReadBytesToWriter reads message from reader and write it to writer.
// First four bytes of reader should be uint32 size of the message,
// represented in big endian.
// Common usage for this function is to read from net.Conn, and write to temp file.
func ReadBytesToWriter(reader io.Reader, writer io.Writer, writeWithSize bool) (n int, err error) {
	// Read message size
	size, err := readSize(reader)
	if err != nil {
		log.Debug(err)
		return 0, err
	}

	if writeWithSize {
		err := writeSize(writer, size)
		if err != nil {
			log.Debug(err)
			return 0, err
		}
	}

	if err = writeErrorCode(writer, nil); err != nil {
		return 0, err
	}

	totalReceived, err := readWrite(reader, writer, size)
	if err != nil {
		return totalReceived, err
	}
	return totalReceived, err
}

// ReadBinary reads file name and file content from a connection and save it.
func ReadBinary(reader io.Reader) error {
	// Read file name
	fileN, err := ReadString(reader)
	if err != nil {
		log.Debug(err)
		log.Error("Error while reading file name")
		return err
	}
	if fileN == "" {
		log.Error("File name cannot be empty")
		return EmptyFileName
	}

	// Read file size
	size, err := readSize(reader)
	if err != nil {
		log.Debug(err)
		log.Error("Error while reading file size")
		return err
	}

	// Read file and save
	if err := readNBinary(reader, size, fileN); err != nil {
		log.Debug(err)
		log.Error("Error while reading/saving binary file")
		return err
	}
	return nil
}

// WriteString writes msg to writer
// length of msg cannot exceed BufferSize
// Returns total bytes sent and error, if any.
// err == nil only if length of sent bytes = length of msg
func WriteString(writer io.Writer, msg string) (int, error) {
	return WriteBytes(writer, []byte(msg))
}

func WriteBytes(writer io.Writer, b []byte) (int, error) {
	return WriteBytesErr(writer, b, nil)
}

// WriteBytesErr write b to writer.
// Returns int indicating the number of bytes written, and error, if any.
func WriteBytesErr(writer io.Writer, b []byte, errorToWrite *common.Error) (n int, err error) {
	//// Return error if b is too big
	//if len(b) > BufferSize {
	//	log.Error("Byte should contain less than ", BufferSize)
	//	return 0, SizeError
	//}

	// Write size of the string to writer
	if err = writeSize(writer, uint32(len(b))); err != nil {
		log.Debug(err)
		log.Error("Error while writing bytes size")
		return 0, err
	}

	// Write Error Code
	if err = writeErrorCode(writer, errorToWrite); err != nil {
		log.Debug(err)
		log.Error("Error while writing error code")
		return 0, err
	}

	// Write b to writer
	writtenSize, err := writer.Write(b)
	if err != nil {
		log.Debug(err)
		log.Error("Error while writing bytes")
		return writtenSize, err
	}
	return writtenSize, err
}

// WriteBinary opens file and writes byte data to writer.
// Returns total length of bytes sent, and error. err == nil only if
// total bytes sent = file size.
// writer is likely to be net.Conn. File size cannot exceed max value of uint32
// as of now. We can split files or change the data type to uint64 if time allows.
func WriteBinary(writer io.Writer, filePath string) (int, error) {
	// Open source file to send
	srcFile, err := os.Open(filePath)
	if err != nil {
		log.Debug(err)
		log.Error("Error while opening source file")
		return 0, err
	}
	// Close src file when done
	defer func() {
		if err := srcFile.Close(); err != nil {
			log.Debug(err)
			log.Error("Error while closing file")
		}
	}()

	// Get stat of the file
	srcFileStat, err := srcFile.Stat()
	if err != nil {
		log.Debug(err)
		log.Error("Error while fetching stats for source file")
		return 0, err
	}

	// If file is too big to send, return error.
	srcFileSize, err := IntToUint32(srcFileStat.Size())
	if err != nil {
		log.Debug(err)
		log.Error("File exceeds size limit")
		return 0, err
	}

	// Only preserve file name instead of passing directory + file name
	_, fileN := filepath.Split(filePath)

	// Send file name
	if _, err := WriteString(writer, fileN); err != nil {
		log.Debug(err)
		log.Error("Error while sending file name")
		return 0, err
	}

	// Write size of the file size to writer
	if err := writeSize(writer, srcFileSize); err != nil {
		log.Debug(err)
		log.Error("Error while writing string size")
		return 0, err
	}

	// Write file to writer
	writtenSize, err := readWrite(srcFile, writer, srcFileSize)
	if err != nil || writtenSize != int(srcFileSize) {
		log.Debug(err)
		log.Error("Error while writing binary file")
		return writtenSize, err
	}
	return writtenSize, nil
}

// readSize reads first 4 bytes from the reader and convert them into a uint32 value
func readSize(reader io.Reader) (uint32, error) {
	// Read first 4 bytes for the size
	b, err := readNBytes(reader, 4)
	if err != nil {
		log.Debug(err)
		log.Error("Error while reading packet size")
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func readErrorCode(reader io.Reader) (readError *common.Error, err error) {
	// Read 1 byte for the error code
	b, err := readNBytes(reader, 1)
	if err != nil {
		log.Debug(err)
		log.Error("Error while reading packet size")
		return nil, err
	}
	if b[0] != 0 {
		readError = common.ErrorCodes[b[0]]
		if readError == nil {
			return common.UnknownCodeError, nil
		}
		return readError, nil
	}
	return nil, nil
}

// Uint32ToByte converts uint32 value to byte slices
func Uint32ToByte(size uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, size)
	return b
}

// Uint16ToByte converts uint16 value to byte slices
func Uint16ToByte(size uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, size)
	return b
}

// ByteToUint16 converts byte slices to uint16
func ByteToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

// writeSize converts packet size to byte and write to writer
// Take a look at encoding/gob package or protocol buffers for a better performance.
func writeSize(writer io.Writer, size uint32) (err error) {
	// consider using array over slice for a better performance i.e: arr := [4]byte{}
	if _, err = writer.Write(Uint32ToByte(size)); err != nil {
		log.Debug(err)
		log.Error("Error while writing packet size")
		return err
	}
	return nil
}

func writeErrorCode(writer io.Writer, errorToWrite *common.Error) (err error) {
	var code uint8 = 0
	if errorToWrite != nil {
		code = errorToWrite.ErrCode
	}
	// Write 1 byte of error code
	if _, err = writer.Write([]byte{code}); err != nil {
		log.Debug(err)
		log.Error("Error while reading packet size")
		return err
	}
	return nil
}

// readNBinary reads up to nth bytes and save it as fileN in DownloadPath.
// Maximum buffer size does not exceed BufferSize.
// Returns error == nil only if file is fully downloaded, renamed and moved to DownloadPath.
func readNBinary(reader io.Reader, n uint32, fileN string) error {
	var isDownloadComplete = false

	// Create directory if it doesn't exist
	if err := os.MkdirAll(DownloadPath, os.ModePerm); err != nil {
		log.Debug(err)
		log.Error("Error while creating download directory")
		return err
	}

	// Create temporary file for downloading
	tmpFile, err := ioutil.TempFile(DownloadPath, ".tmp_download_")
	if err != nil {
		log.Debug(err)
		log.Error("Temp file could not be opened")
		return err
	}

	// If error encountered while writing a file, close then delete tmp file.
	defer func(name string) {
		if !isDownloadComplete {
			if err := tmpFile.Close(); err != nil {
				log.Debug(err)
				log.Error("Error while closing the file.")
			}
			// Delete file if not renamed
			if err := os.Remove(name); err != nil {
				log.Debug(err)
				log.Error("Error while removing temp file. Temp file at: ", name)
			}
		}
	}(tmpFile.Name())

	if writtenSize, err := readWrite(reader, tmpFile, n); writtenSize != int(n) || err != nil {
		log.Debug(err)
		log.Error("Error while reading from reader and writing to temp file")
		return err
	}
	isDownloadComplete = true

	// Close I/O operation for temporary file
	if err := tmpFile.Close(); err != nil {
		log.Debug(err)
		log.Error("Error while closing temp file.")
		return err
	}

	// Move temporary file to download directory (DownloadPath)
	if err := os.Rename(tmpFile.Name(), filepath.Join(DownloadPath, fileN)); err != nil {
		log.Debug(err)
		log.Error("Error moving the temp file to download path")
		if err := os.Remove(tmpFile.Name()); err != nil {
			log.Debug(err)
			log.Error("Error while removing temp file. Temp file at: ", tmpFile.Name())
		}
		return err
	}
	return nil
}

// readNString reads up to nth character. Maximum length should not exceed BufferSize.
func readNString(reader io.Reader, n uint32) (string, error) {
	if n > BufferSize {
		log.Error("n should be smaller than ", BufferSize)
		return "", errors.New("parameter value error")
	}
	buffer, err := readNBytes(reader, n)
	return string(buffer), err
}

// readNBytes reads up to nth byte
func readNBytes(reader io.Reader, n uint32) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	buffer := make([]byte, n)
	_, err := io.ReadFull(reader, buffer)
	return buffer, err
}

// readNBytes reads up to nth byte
func readNBytesPointer(reader io.Reader, buffer *[]byte) error {
	_, err := io.ReadFull(reader, *buffer)
	return err
}

// readWrite is a helper function to read exactly size bytes from reader and write it to writer.
// Returns length of bytes written and error, if any. Error = nil only if length of bytes
// written = size.
func readWrite(reader io.Reader, writer io.Writer, size uint32) (int, error) {
	totalReceived := 0
	intSize := int(size)
	readSize := BufferSize
	buffer := bufPool.Get().([]byte)
	for totalReceived < intSize {
		if totalReceived+BufferSize > intSize {
			readSize = intSize - totalReceived
		}
		read, err := io.ReadFull(reader, buffer[:readSize])
		if err != nil || read != readSize {
			log.Debug(err)
			return totalReceived, err
		}
		written, err := writer.Write(buffer[:readSize])
		totalReceived += written
		if err != nil {
			log.Debug(err)
			return totalReceived, err
		}
	}
	bufPool.Put(buffer)
	return totalReceived, nil
}

// IntToUint32 converts int64 value to uint32.
// Returns value and error. If value occurs overflow, 0 and error is returned
func IntToUint32(n int64) (uint32, error) {
	if n < 0 || n > Uint32Max {
		log.Error("value ", n, " overflows uint32")
		return 0, errors.New("value overflows uint32")
	}
	return uint32(n), nil
}

// CheckIPAddress check if ip address is valid or not
func CheckIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// WriteConfig writes config to fileName in yaml format
func WriteConfig(fileName string, config interface{}) (err error) {
	dstFile, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		log.Debug(err)
		log.Error("Error while creating file for config")
		return err
	}
	defer func() {
		if err := dstFile.Close(); err != nil {
			log.Debug(err)
			log.Error("Error while closing config file")
			return
		}
	}()

	marshal, err := yaml.Marshal(&config)
	if err != nil {
		log.Debug(err)
		log.Error("Error while converting serv struct to []byte")
		return err
	}

	if _, err := dstFile.Write(marshal); err != nil {
		log.Debug(err)
		log.Error("Error while writing config file")
		return err
	}

	return nil
}

// BytesToBase64 encodes raw bytes to base64-encoded bytes
func BytesToBase64(data []byte) []byte {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data[:])
	return encoded
}
