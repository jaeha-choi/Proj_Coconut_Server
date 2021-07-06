package util

import (
	"encoding/binary"
	"errors"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
)

const (
	bufferSize   = 4096
	uint32Max    = 4294967295
	downloadPath = "./downloaded"
)

// ReadString reads string from a connection
func ReadString(reader io.Reader) (string, error) {
	// Read packet size (string size)
	size, err := readSize(reader)
	if err != nil {
		log.Debug(err)
		log.Error("Error while reading string size")
		return "", err
	}

	// ReadString always expect the size to be <= bufferSize
	if size > bufferSize {
		log.Error("String size cannot be greater than ", bufferSize, ". String size: ", size)
		return "", errors.New("size exceeded")
	}

	// Read string from the packet
	str, err := readNString(reader, size)
	if err != nil {
		log.Debug(err)
		log.Error("Error while reading string")
		return "", err
	}
	return str, nil
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
		return errors.New("empty filename")
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
// length of msg cannot exceed bufferSize
// Returns total bytes sent and error, if any.
// err == nil only if length of sent bytes = length of msg
func WriteString(writer io.Writer, msg string) (int, error) {
	// Return error if msg is too big
	if len(msg) > bufferSize {
		log.Error("String should contain less than ", bufferSize, " characters")
		return 0, errors.New("size exceeded")
	}

	// Write size of the string to writer
	if err := writeSize(writer, uint32(len(msg))); err != nil {
		log.Debug(err)
		log.Error("Error while writing string size")
		return 0, err
	}

	// Write msg to writer
	writtenSize, err := writer.Write([]byte(msg))
	if writtenSize != len(msg) || err != nil {
		log.Debug(err)
		log.Error("Error while writing string")
		return writtenSize, err
	}
	return writtenSize, err
}

// WriteBinary opens file and writes byte data to writer.
// Returns total length of bytes sent, and error. err == nil only if
// total bytes sent = file size.
// writer is likely to be net.Conn. File size cannot exceed max value of uint32
// as of now. We can split files or change the data type to uint64 if time allows.
func WriteBinary(writer io.Writer, filePath string) (uint32, error) {
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
	if writtenSize != srcFileSize || err != nil {
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

// writeSize converts packet size to byte and write to writer
// Take a look at encoding/gob package or protocol buffers for a better performance.
func writeSize(writer io.Writer, size uint32) error {
	// consider using array over slice for a better performance i.e: arr := [4]byte{}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, size)
	_, err := writer.Write(b)
	if err != nil {
		log.Debug(err)
		log.Error("Error while writing packet size")
		return err
	}
	return nil
}

// readNBinary reads up to nth bytes and save it as fileN in downloadPath.
// Maximum buffer size does not exceed bufferSize.
// Returns error == nil only if file is fully downloaded, renamed and moved to downloadPath.
func readNBinary(reader io.Reader, n uint32, fileN string) error {
	var isDownloadComplete = false

	// Create directory if it doesn't exist
	if err := os.MkdirAll(downloadPath, os.ModePerm); err != nil {
		log.Debug(err)
		log.Error("Error while creating download directory")
		return err
	}

	// Create temporary file for downloading
	tmpFile, err := ioutil.TempFile(downloadPath, ".tmp_download_")
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

	if writtenSize, err := readWrite(reader, tmpFile, n); writtenSize != n || err != nil {
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

	// Move temporary file to download directory (downloadPath)
	if err := os.Rename(tmpFile.Name(), filepath.Join(downloadPath, fileN)); err != nil {
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

// readNString reads up to nth character. Maximum length should not exceed bufferSize.
func readNString(reader io.Reader, n uint32) (string, error) {
	if n > bufferSize {
		log.Error("n should be smaller than ", bufferSize)
		return "", errors.New("parameter value error")
	}
	buffer, err := readNBytes(reader, n)
	return string(buffer), err
}

// readNBytes reads up to nth byte
func readNBytes(reader io.Reader, n uint32) ([]byte, error) {
	buffer := make([]byte, n)
	_, err := io.ReadFull(reader, buffer)
	return buffer, err
}

// readWrite is a helper function to read exactly size bytes from reader and write it to writer.
// Returns length of bytes written and error, if any. Error = nil only if length of bytes
// written = size.
func readWrite(reader io.Reader, writer io.Writer, size uint32) (uint32, error) {
	var totalReceived uint32 = 0
	var receivedLen int
	var err error
	var buffSize uint32

	// Determine buffer size
	if size < bufferSize {
		buffSize = size
	} else {
		buffSize = bufferSize
	}

	// Create buffer
	buffer := make([]byte, buffSize)

	// Repeat downloading until the file is fully received
	for totalReceived < size {
		// Last portion of the data
		if totalReceived+buffSize > size {
			buffer, err = io.ReadAll(io.LimitReader(reader, int64(size-totalReceived)))
			receivedLen = len(buffer)
			// If reader contains less than expected size
			if totalReceived+uint32(receivedLen) != size {
				log.Error("File not fully received")
				return totalReceived + uint32(receivedLen), errors.New("unexpected EOF")
			}
		} else {
			receivedLen, err = io.ReadFull(reader, buffer)
		}

		if err != nil {
			log.Debug(err)
			log.Error("Error while receiving bytes")
			return totalReceived, err
		}

		// Write to writer
		writtenLen, err := writer.Write(buffer)
		if writtenLen != receivedLen || err != nil {
			log.Debug(err)
			log.Error("Error while writing to a file")
			return totalReceived + uint32(writtenLen), err
		}
		totalReceived += uint32(receivedLen)
	}
	return totalReceived, nil
}

// IntToUint32 converts int64 value to uint32.
// Returns value and error. If value occurs overflow, 0 and error is returned
func IntToUint32(n int64) (uint32, error) {
	if n < 0 || n > uint32Max {
		log.Error("value ", n, " overflows uint32")
		return 0, errors.New("value overflows uint32")
	}
	return uint32(n), nil
}

// CheckIPAddress check if ip address is valid or not
func CheckIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}
