package util

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func init() {
	log.Init(os.Stdout, log.DEBUG)
}

func TestReadBinary(t *testing.T) {
	t.Cleanup(CleanupHelper)
	// Create reader for destination file
	dstFileN := "cat_result.jpg"
	destFileNSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(len(dstFileN))))
	destFileNReader := bytes.NewReader([]byte(dstFileN))

	// Create reader for source file
	srcFileN := "../testdata/cat.jpg"

	srcFileReader, err := os.Open(srcFileN)
	if err != nil || srcFileReader == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := srcFileReader.Close(); err != nil {
			log.Debug(err)
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	srcFileStat, err := srcFileReader.Stat()
	if err != nil || srcFileStat == nil {
		log.Debug(err)
		t.Error("Error while getting image file stats")
		return
	}
	srcFileSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(srcFileStat.Size())))
	errCodeReader := bytes.NewReader([]byte{0})
	errCodeReader2 := bytes.NewReader([]byte{0})

	// Combine all readers
	readers := io.MultiReader(destFileNSizeReader, errCodeReader, destFileNReader, srcFileSizeReader, errCodeReader2, srcFileReader)

	errCode, err := ReadBinary(readers)

	if err != nil {
		log.Debug(err)
		t.Error("Error in ReadBinary")
		return
	}

	if errCode != nil {
		log.Debug(errCode)
		t.Error("Error in ReadBinary")
		return
	}

	// Open result image
	resImgFile, err := os.Open(filepath.Join(DownloadPath, dstFileN))
	if err != nil || resImgFile == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := resImgFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Error while closing image file")
		}
	}()

	// Reset reader offset since the file was already read once
	_, err = srcFileReader.Seek(0, 0)
	if err != nil {
		log.Debug(err)
		t.Error("Error while resetting reader offset")
		return
	}

	// If checksum does not match, return error
	if !ChecksumMatch(t, srcFileReader, resImgFile) {
		t.Error("Checksum does not match")
		return
	}
}

func TestReadBinaryEmptyFileNSizeError(t *testing.T) {
	t.Cleanup(CleanupHelper)
	// Use super long text for file name
	dstFileNFile := "../testdata/test_8192.txt"
	fileNFile, err := os.Open(dstFileNFile)
	if err != nil {
		log.Debug(err)
		t.Error("Cannot read the input file")
		return
	}
	// Close file when done
	defer func() {
		if err = fileNFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Input file not properly closed")
		}
	}()
	fileNFileSizeReader := bytes.NewReader(sizeToBytesHelper(t, 8192))

	// Combine all readers
	readers := io.MultiReader(fileNFileSizeReader, fileNFile)

	if errCode, err := ReadBinary(readers); err == nil || errCode != nil {
		t.Error("Expected error, but no error was raised.")
		return
	}
}

func TestReadBinaryEmptyFileNError(t *testing.T) {
	t.Cleanup(CleanupHelper)
	// Create reader for destination file
	dstFileN := ""
	destFileNSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(len(dstFileN))))
	destFileNReader := bytes.NewReader([]byte(dstFileN))

	// Create reader for source file
	srcFileN := "../testdata/cat.jpg"

	srcFileReader, err := os.Open(srcFileN)
	if err != nil || srcFileReader == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := srcFileReader.Close(); err != nil {
			log.Debug(err)
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	srcFileStat, err := srcFileReader.Stat()
	if err != nil || srcFileStat == nil {
		log.Debug(err)
		t.Error("Error while getting image file stats")
		return
	}
	srcFileSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(srcFileStat.Size())))

	// Combine all readers
	readers := io.MultiReader(destFileNSizeReader, destFileNReader, srcFileSizeReader, srcFileReader)

	if _, err := ReadBinary(readers); err == nil {
		t.Error("Expected error, but no error was raised.")
		return
	}
}

func TestReadBinaryIncorrectFileSize(t *testing.T) {
	t.Cleanup(CleanupHelper)
	// Create reader for destination file
	dstFileN := "cat_result.jpg"
	destFileNSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(len(dstFileN))))
	destFileNReader := bytes.NewReader([]byte(dstFileN))

	// Create reader for source file
	srcFileN := "../testdata/cat.jpg"

	srcFileReader, err := os.Open(srcFileN)
	if err != nil || srcFileReader == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := srcFileReader.Close(); err != nil {
			log.Debug()
			t.Error("Error while closing image file")
		}
	}()

	incorrectFileSize := make([]byte, 2)
	srcFileSizeReader := bytes.NewReader(incorrectFileSize)

	// Combine all readers
	readers := io.MultiReader(destFileNSizeReader, destFileNReader, srcFileSizeReader)

	if _, err := ReadBinary(readers); err == nil {
		t.Error("Expected error, but no error was raised.")
	}
}

func TestReadBinaryShortReader(t *testing.T) {
	t.Cleanup(CleanupHelper)
	// Create reader for destination file
	dstFileN := "cat_result.jpg"
	destFileNSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(len(dstFileN))))
	destFileNReader := bytes.NewReader([]byte(dstFileN))

	// Create reader for source file
	srcFileN := "../testdata/cat.jpg"

	srcFileReader, err := os.Open(srcFileN)
	if err != nil || srcFileReader == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := srcFileReader.Close(); err != nil {
			log.Debug(err)
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	srcFileStat, err := srcFileReader.Stat()
	if err != nil || srcFileStat == nil {
		log.Debug(err)
		t.Error("Error while getting image file stats")
		return
	}
	srcFileSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(srcFileStat.Size())))

	limitedFile := io.LimitReader(srcFileReader, srcFileStat.Size()-100)
	// Combine all readers
	readers := io.MultiReader(destFileNSizeReader, destFileNReader, srcFileSizeReader, limitedFile)

	if _, err := ReadBinary(readers); err == nil {
		t.Error("Expected error, but no error was raised.")
	}
}

func TestReadWriteString(t *testing.T) {
	var buffer bytes.Buffer
	msg := "test msg"

	// Test WriteString
	if writtenLen, err := WriteString(&buffer, msg); err != nil || writtenLen != len(msg) {
		log.Debug(err)
		t.Error("Error in WriteString")
		return
	}

	// Test ReadString
	resultStr, err := ReadString(&buffer)
	if err != nil {
		log.Debug(err)
		t.Error("Error in ReadString")
		return
	}

	// Verify string
	if msg != resultStr {
		log.Debug("Msg: ", msg)
		log.Debug("ResultStr: ", resultStr)
		t.Error("Result does mismatch")
		return
	}
}

func TestWriteString(t *testing.T) {
	var buffer bytes.Buffer
	msg := "test msg"

	if writtenLen, err := WriteString(&buffer, msg); err != nil || writtenLen != len(msg) {
		log.Debug(err)
		t.Error("Error in WriteString")
		return
	}

	// Read first four bytes for size
	strSize, err := ioutil.ReadAll(io.LimitReader(&buffer, 4))
	if err != nil {
		log.Debug(err)
		t.Error("Error while getting string length")
		return
	}

	// Check size
	size := binary.BigEndian.Uint32(strSize)
	if size != uint32(len(msg)) {
		log.Debug("Size: ", size)
		log.Debug("Msg Len: ", len(msg))
		t.Error("Size does not match")
	}

	if errCode, err := readErrorCode(&buffer); err != nil || errCode != nil {
		log.Debug(err)
		t.Error("Error while reading error Code")
	}

	// Read the rest (since this test does not contain any other data)
	b, err := ioutil.ReadAll(&buffer)
	if err != nil {
		log.Debug(err)
		t.Error("Error while reading buffer")
		return
	}

	// Verify string
	if msg != string(b) {
		log.Debug(string(b))
		t.Error("Result mismatch")
		return
	}
}

func TestReadNBinary(t *testing.T) {
	t.Cleanup(CleanupHelper)
	testFileN := "../testdata/cat.jpg"
	resultFileN := "cat_result.jpg"

	// Open original image
	imgFile, err := os.Open(testFileN)
	if err != nil || imgFile == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := imgFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	imgFileStat, err := imgFile.Stat()
	if err != nil || imgFileStat == nil {
		log.Debug(err)
		t.Error("Error while getting image file stats")
		return
	}

	if err = readNBinary(imgFile, uint32(imgFileStat.Size()), resultFileN); err != nil {
		log.Debug(err)
		t.Error("Error encountered while reading binary")
		return
	}

	// Open result image
	resImgFile, err := os.Open(filepath.Join(DownloadPath, resultFileN))
	if err != nil || resImgFile == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := resImgFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Error while closing image file")
		}
	}()

	// Reset reader offset since the file was already read once
	if _, err = imgFile.Seek(0, 0); err != nil {
		log.Debug(err)
		t.Error("Error while resetting reader offset")
		return
	}

	if !ChecksumMatch(t, imgFile, resImgFile) {
		t.Error("Checksum does not match")
		return
	}
}

func TestReadNBinaryTiny(t *testing.T) {
	t.Cleanup(CleanupHelper)

	testFileN := "../testdata/pine_cone.jpg"
	resultFileN := "pine_cone_result.jpg"

	// Open original image
	imgFile, err := os.Open(testFileN)
	if err != nil || imgFile == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := imgFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	imgFileStat, err := imgFile.Stat()
	if err != nil || imgFileStat == nil {
		log.Debug(err)
		t.Error("Error while getting image file stats")
		return
	}

	if err := readNBinary(imgFile, uint32(imgFileStat.Size()), resultFileN); err != nil {
		log.Debug(err)
		t.Error("Error encountered while reading binary")
		return
	}

	// Open result image
	resImgFile, err := os.Open(filepath.Join(DownloadPath, resultFileN))
	if err != nil || resImgFile == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := resImgFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Error while closing image file")
		}
	}()

	// Reset reader offset since the file was already read once
	if _, err = imgFile.Seek(0, 0); err != nil {
		log.Debug(err)
		t.Error("Error while resetting reader offset")
		return
	}

	if !ChecksumMatch(t, imgFile, resImgFile) {
		t.Error("Checksum does not match")
		return
	}
}

func TestReadWriteBinary(t *testing.T) {
	t.Cleanup(CleanupHelper)
	srcFileN := "../testdata/cat.jpg"
	var buffer bytes.Buffer

	// Test WriteBinary
	if _, err := WriteBinary(&buffer, srcFileN); err != nil {
		log.Debug(err)
		t.Error("Error in WriteBinary")
		return
	}

	// Test ReadBinary
	if _, err := ReadBinary(&buffer); err != nil {
		log.Debug(err)
		t.Error("Error in ReadBinary")
		return
	}

	// Open "sent" file
	expected, err := os.Open(srcFileN)
	if err != nil {
		log.Debug(err)
		t.Error("Error while opening src file")
		return
	}

	// Open "received" file
	result, err := os.Open(filepath.Join(DownloadPath, "cat.jpg"))
	if err != nil {
		log.Debug(err)
		t.Error("Error while opening dst file")
		return
	}

	// Compare checksum
	if !ChecksumMatch(t, expected, result) {
		t.Error("Checksum mismatch")
		return
	}
}

func TestReadNBinaryCreateDirError(t *testing.T) {
	t.Cleanup(CleanupHelper)
	testFileN := "../testdata/cat.jpg"
	resultFileN := "cat_result.jpg"

	// Open original image
	imgFile, err := os.Open(testFileN)
	if err != nil || imgFile == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := imgFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	imgFileStat, err := imgFile.Stat()
	if err != nil || imgFileStat == nil {
		log.Debug(err)
		t.Error("Error while getting image file stats")
		return
	}

	// Create new file to prevent downloaded directory from being created
	newFileN := DownloadPath
	newFile, err := os.Create(newFileN)
	if err != nil || newFile == nil {
		log.Debug(err)
		t.Error("Error while creating a file")
		return
	}
	if err := newFile.Close(); err != nil {
		log.Debug(err)
		t.Error("Error while creating a file")
		return
	}

	if err := readNBinary(imgFile, uint32(imgFileStat.Size()), resultFileN); err == nil {
		t.Error("Expected error while readNBinary, but no error was raised.")
		return
	}
}

func TestReadNBinaryTinyWrongSize(t *testing.T) {
	t.Cleanup(CleanupHelper)
	testFileN := "../testdata/pine_cone.jpg"
	resultFileN := "pine_cone_result.jpg"

	// Open original image
	imgFile, err := os.Open(testFileN)
	if err != nil || imgFile == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := imgFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	imgFileStat, err := imgFile.Stat()
	if err != nil || imgFileStat == nil {
		t.Error("Error while getting image file stats")
		return
	}

	if err := readNBinary(imgFile, uint32(imgFileStat.Size()+1), resultFileN); err == nil {
		t.Error("Expected error, but no error was raised.")
		return
	}
}

func TestReadNBinaryTinyWrongSize2(t *testing.T) {
	t.Cleanup(CleanupHelper)
	testFileN := "../testdata/cat.jpg"
	resultFileN := "cat_result.jpg"

	// Open original image
	imgFile, err := os.Open(testFileN)
	if err != nil || imgFile == nil {
		log.Debug(err)
		t.Error("Error opening image file")
		return
	}
	defer func() {
		if err := imgFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	imgFileStat, err := imgFile.Stat()
	if err != nil || imgFileStat == nil {
		log.Debug(err)
		t.Error("Error while getting image file stats")
		return
	}
	//log.Debug(imgFileStat.Size())
	partial := io.LimitReader(imgFile, 51283)

	if err := readNBinary(partial, uint32(imgFileStat.Size()), resultFileN); err == nil {
		t.Error("Expected error, but no error was raised.")
		return
	}
}

func TestReadString(t *testing.T) {
	testStr := "test this"

	sizeBytes := sizeToBytesHelper(t, uint32(len(testStr)))
	sizeReader := bytes.NewReader(sizeBytes)
	errCodeReader := bytes.NewReader([]byte{0})
	strReader := bytes.NewReader([]byte(testStr))
	reader := io.MultiReader(sizeReader, errCodeReader, strReader)

	if resultStr, err := ReadString(reader); err != nil || resultStr != testStr {
		log.Debug("Result: ", resultStr)
		log.Debug("Expected: ", testStr)
		log.Debug(err)
		t.Error("Read string returned incorrect result")
		return
	}
}

func TestReadStringSizeError(t *testing.T) {
	sizeBytes := make([]byte, 2)
	sizeReader := bytes.NewReader(sizeBytes)

	if _, err := ReadString(sizeReader); err == nil {
		t.Error("Expected error when reading size, but no error raised.")
		return
	}
}

func TestReadStringSizeMax(t *testing.T) {
	//t.Skip()
	// Open input file for testing
	file, err := os.Open("../testdata/test_4096.txt")
	if err != nil {
		log.Debug(err)
		t.Error("Cannot read the input file")
		return
	}

	// Close file when done
	defer func() {
		if err = file.Close(); err != nil {
			log.Debug(err)
			t.Error("Input file not properly closed")
		}
	}()

	sizeReader := bytes.NewReader(sizeToBytesHelper(t, 4096))
	errCodeReader := bytes.NewReader([]byte{0})

	reader := io.MultiReader(sizeReader, errCodeReader, file)

	result, err := ReadString(reader)
	if err != nil {
		log.Debug(err)
		t.Error("Error while reading string")
		return
	}

	// Reset reader offset since the file was already read once
	if _, err = file.Seek(0, 0); err != nil {
		log.Debug(err)
		t.Error("Error while resetting reader offset")
		return
	}

	// Read input file as string
	input, err := io.ReadAll(reader)
	if err != nil {
		log.Debug(err)
		t.Error("Error while reading from input file")
		return
	}

	if string(input)[:4096] != result {
		log.Debug("Input: ", string(input))
		log.Debug("----------------")
		log.Debug("Result: ", result)
		t.Error("Result does not match input")
		return
	}
}

func TestReadStringSizeExceedMax(t *testing.T) {
	// Open input file for testing
	file, err := os.Open("../testdata/test_8192.txt")
	if err != nil {
		log.Debug(err)
		t.Error("Cannot read the input file")
		return
	}

	// Close file when done
	defer func() {
		if err := file.Close(); err != nil {
			log.Debug(err)
			t.Error("Input file not properly closed")
		}
	}()
	sizeReader := bytes.NewReader(sizeToBytesHelper(t, 8192))
	reader := io.MultiReader(sizeReader, file)

	if _, err = ReadString(reader); err == nil {
		t.Error("Expected error, but no error raised.")
		return
	}
}

func TestReadStringSizeShortReader(t *testing.T) {
	testStr := "test this"

	sizeBytes := sizeToBytesHelper(t, 1024)
	sizeReader := bytes.NewReader(sizeBytes)
	strReader := bytes.NewReader([]byte(testStr))
	reader := io.MultiReader(sizeReader, strReader)

	if result, err := ReadString(reader); result != "" || err == nil {
		t.Error("Expected error, but no error raised.")
		return
	}
}

func TestReadSizeError(t *testing.T) {
	inputBytes := make([]byte, 2)
	// [0 0]
	reader := bytes.NewReader(inputBytes)
	if result, err := readSize(reader); err == nil || result != 0 {
		t.Error("Expected error, but no error raised.")
		return
	}
}

func TestReadSize0(t *testing.T) {
	inputBytes := make([]byte, 4)
	// [0 0 0 0]
	reader := bytes.NewReader(inputBytes)
	if result, err := readSize(reader); err != nil || result != 0 {
		log.Debug(err)
		t.Error("Error while reading size [0]")
		return
	}
}

func TestReadSize255(t *testing.T) {
	inputBytes := make([]byte, 4)
	// [0 0 0 255]
	inputBytes[3] = 255
	reader := bytes.NewReader(inputBytes)
	if result, err := readSize(reader); err != nil || result != 255 {
		log.Debug(err)
		t.Error("Error while reading size [255]")
		return
	}
}

func TestReadSize4095(t *testing.T) {
	inputBytes := make([]byte, 4)
	// [0 0 15 255]
	inputBytes[2] = 15
	inputBytes[3] = 255
	reader := bytes.NewReader(inputBytes)
	if result, err := readSize(reader); err != nil || result != 4095 {
		log.Debug(err)
		t.Error("Error while reading size [4095]")
		return
	}
}

func TestReadSizeMax(t *testing.T) {
	inputBytes := make([]byte, 4)
	// [255 255 255 255]
	inputBytes[0] = 255
	inputBytes[1] = 255
	inputBytes[2] = 255
	inputBytes[3] = 255
	reader := bytes.NewReader(inputBytes)
	if result, err := readSize(reader); err != nil || result != Uint32Max {
		log.Debug(err)
		t.Error("Error while reading size uint32max")
		return
	}
}

func TestWriteSize0(t *testing.T) {
	result := sizeToBytesHelper(t, 0)
	expected := make([]byte, 4)
	// [0 0 0 0]
	if bytes.Compare(result, expected) != 0 {
		log.Debug("Result: ", result)
		log.Debug("Expected: ", expected)
		t.Error("Incorrect value returned")
		return
	}
}

func TestWriteSize255(t *testing.T) {
	result := sizeToBytesHelper(t, 255)
	expected := make([]byte, 4)
	// [0 0 0 255]
	expected[3] = 255
	if bytes.Compare(result, expected) != 0 {
		log.Debug("Result: ", result)
		log.Debug("Expected: ", expected)
		t.Error("Incorrect value returned")
		return
	}
}

func TestWriteSize4095(t *testing.T) {
	result := sizeToBytesHelper(t, 4095)
	expected := make([]byte, 4)
	// [0 0 15 255]
	expected[2] = 15
	expected[3] = 255
	if bytes.Compare(result, expected) != 0 {
		log.Debug("Result: ", result)
		log.Debug("Expected: ", expected)
		t.Error("Incorrect value returned")
		return
	}
}

func TestWriteSizeMax(t *testing.T) {
	result := sizeToBytesHelper(t, 4294967295)
	expected := make([]byte, 4)
	// [255 255 255 255]
	expected[0] = 255
	expected[1] = 255
	expected[2] = 255
	expected[3] = 255
	if bytes.Compare(result, expected) != 0 {
		log.Debug("Result: ", result)
		log.Debug("Expected: ", expected)
		t.Error("Incorrect value returned")
		return
	}
}

func TestReadNString(t *testing.T) {
	reader := strings.NewReader("init 1234 prev 5678 curr next \n")
	if s, err := readNString(reader, 22); err != nil || s != "init 1234 prev 5678 cu" {
		log.Debug(err)
		t.Error("Incorrect result.")
		return
	}
}

func TestReadNStringBufferSize(t *testing.T) {
	// Open input file for testing
	file, err := os.Open("../testdata/test_4096.txt")
	if err != nil {
		log.Debug(err)
		t.Error("Cannot read the input file")
		return
	}

	// Close file when done
	defer func() {
		if file != nil {
			if err := file.Close(); err != nil {
				log.Debug(err)
				t.Error("Input file not properly closed")
			}
		}
	}()

	// Test readNString
	reader := bufio.NewReader(file)
	s, err := readNString(reader, 4096)
	if err != nil {
		log.Debug(err)
		t.Error("readNString returned error")
		return
	}

	// Create temp file
	tmpFile, err := ioutil.TempFile("", "tmp")
	if err != nil {
		log.Debug(err)
		t.Error("Error while creating temp file")
		return
	}

	// Close and delete temp file when done
	defer func(name string) {
		if err := tmpFile.Close(); err != nil {
			log.Debug(err)
			t.Error("Temp file not closed.")
		}
		// Disable this statement to prevent the program from deleting
		// the file after testing
		if err := os.Remove(name); err != nil {
			log.Debug(err)
			log.Info("Temp file: ", name)
			t.Error("Temp file not removed.")
		}
	}(tmpFile.Name())

	// Write to tmp file for debugging
	if _, err := tmpFile.WriteString(s); err != nil {
		log.Debug(err)
		t.Error("Error while writing output file.")
		return
	}

	// To guarantee the file to be written on disk before comparing
	if err := tmpFile.Sync(); err != nil {
		log.Debug(err)
		t.Error("File not written to disk")
		return
	}

	// Reset reader offset since the file was already read once
	if _, err := file.Seek(0, 0); err != nil {
		log.Debug(err)
		t.Error("Error while resetting reader offset")
		return
	}

	// Reset reader offset since the file was already read once
	if _, err := tmpFile.Seek(0, 0); err != nil {
		log.Debug(err)
		t.Error("Error while setting reader offset")
		return
	}

	if !ChecksumMatch(t, file, tmpFile) {
		t.Error("checksum does not match")
		return
	}
}

func TestReadNStringMaxSizePlugOne(t *testing.T) {
	// Open input file for testing
	file, err := os.Open("../testdata/test_4096.txt")
	if err != nil {
		log.Debug(err)
		t.Error("Cannot read the input file")
		return
	}

	// Close file when done
	defer func() {
		if file != nil {
			if err := file.Close(); err != nil {
				log.Debug(err)
				t.Error("Input file not properly closed")
			}
		}
	}()

	// Reset reader offset since the file was already read once
	if _, err := file.Seek(0, 0); err != nil {
		log.Debug(err)
		t.Error("Error while resetting reader offset")
		return
	}

	// Test readNString
	reader := bufio.NewReader(file)
	if s, err := readNString(reader, 4097); s != "" || err == nil {
		log.Debug(err)
		t.Error("Expected error, but error was not raised")
		return
	}
}

func TestReadNStringBufferSizeMinusOne(t *testing.T) {
	// Open input file for testing
	file, err := os.Open("../testdata/test_4096.txt")
	if err != nil {
		log.Debug(err)
		t.Error("Cannot read the input file")
		return
	}

	// Close file when done
	defer func() {
		if file != nil {
			if err := file.Close(); err != nil {
				log.Debug(err)
				t.Error("Input file not properly closed")
			}
		}
	}()

	// Test readNString
	reader := bufio.NewReader(file)
	s, err := readNString(reader, 4095)
	if err != nil {
		log.Debug(err)
		t.Error("error in readNString")
		return
	}

	tmpReader := strings.NewReader(s[:4095])

	// Reset reader offset since the file was already read once
	if _, err := file.Seek(0, 0); err != nil {
		log.Debug(err)
		t.Error("Error while resetting reader offset")
		return
	}
	inputReader := io.LimitReader(file, 4095)

	if !ChecksumMatch(t, inputReader, tmpReader) {
		t.Error("checksum does not match")
		return
	}
}

func TestReadNStringZero(t *testing.T) {
	reader := strings.NewReader("init 1234 prev 5678 curr next \n")
	if s, err := readNString(reader, 0); err != nil || s != "" {
		log.Debug(err)
		t.Error("Incorrect result.")
		return
	}
}

func TestReadNStringExceed(t *testing.T) {
	reader := strings.NewReader("init 1234 prev 5678 curr next \n")
	if _, err := readNString(reader, 50); err == nil {
		t.Error("Expected error, but no error raised.")
		return
	}
}

func TestIntToUint32SignedInt(t *testing.T) {
	if val, err := IntToUint32(-1); val != 0 || err == nil {
		t.Error("Expected error, but no error raised.")
		return
	}
}

func TestIntToUint32Max(t *testing.T) {
	if val, err := IntToUint32(4294967296); val != 0 || err == nil {
		t.Error("Expected error, but no error raised.")
		return
	}
}

func TestIntToUint32(t *testing.T) {
	if val, err := IntToUint32(27532); val != 27532 || err != nil {
		log.Debug(err)
		t.Error("Error during conversion")
		return
	}
}

func sizeToBytesHelper(t *testing.T, size uint32) []byte {
	t.Helper()
	// consider using array over slice for a better performance i.e: arr := [4]byte{}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, size)
	return b
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

func TestCheckIPAddressValidIpv4(t *testing.T) {
	validIPV4 := "10.40.210.253"
	if !CheckIPAddress(validIPV4) {
		t.Error("TestCheckIPAddressValidIpv4 is invalid")
		return
	}
}

func TestCheckIPAddressInvalidIpv4(t *testing.T) {
	invalidIPV4 := "1000.40.210.253"
	if CheckIPAddress(invalidIPV4) {
		t.Error("TestCheckIPAddressInvalidIpv4 is invalid")
		return
	}
}

func TestCheckIPAddressValidIpv6(t *testing.T) {
	validIPV6 := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	if !CheckIPAddress(validIPV6) {
		t.Error("TestCheckIPAddressValidIpv6 is invalid")
		return
	}
}

func TestCheckIPAddressInvalidIpv6(t *testing.T) {
	invalidIPV6 := "2001:0db8:85a3:0000:0000:8a2e:0370:7334:3445"
	if CheckIPAddress(invalidIPV6) {
		t.Error("TestCheckIPAddressInvalidIpv6 is invalid")
		return
	}
}

func CleanupHelper() {
	// Remove DownloadPath after testing
	if err := os.RemoveAll(DownloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}

func TestReadBytesTemp(t *testing.T) {
	var buf bytes.Buffer
	var output bytes.Buffer

	err := writeSize(&buf, 4100)
	if err != nil {
		t.Error()
		return
	}
	testByte, err := ioutil.ReadFile("../testdata/test_4096.txt")
	if err != nil {
		t.Error(err)
	}
	buf.Write(testByte)
	testByte = []byte("test")
	buf.Write(testByte)
	temp, err := ReadBytesToWriter(&buf, &output, false)
	if err != nil || temp != 4100 {
		t.Error(err)
		return
	}
}

func BenchmarkReadNBytes(b *testing.B) {
	var buf bytes.Buffer
	//testByte, err := ioutil.ReadFile("../testdata/test_4096.txt")
	//if err != nil{
	//	b.Error(err)
	//}
	testByte := []byte("test")
	for i := 0; i < b.N; i++ {
		buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		_, err := readNBytes(&buf, 4)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkReadNBytesPointer(b *testing.B) {
	var buf bytes.Buffer
	buffer := make([]byte, 4)
	//testByte, err := ioutil.ReadFile("../testdata/test_4096.txt")
	//if err != nil{
	//	b.Error(err)
	//}
	testByte := []byte("test")
	for i := 0; i < b.N; i++ {
		buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		//buf.Write(testByte)
		err := readNBytesPointer(&buf, &buffer)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkReadWrite(b *testing.B) {
	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		testFile, err := os.Open("../testdata/test_4096.txt")
		if err != nil {
			b.Error(err)
		}

		if _, err = readWrite(testFile, &buf, 4096); err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkReadBytesTemp(b *testing.B) {
	var buf bytes.Buffer
	var output bytes.Buffer

	for i := 0; i < b.N; i++ {
		err := writeSize(&buf, 4100)
		if err != nil {
			b.Error()
			return
		}
		testByte, err := ioutil.ReadFile("../testdata/test_4096.txt")
		if err != nil {
			b.Error(err)
		}
		buf.Write(testByte)
		buf.Write([]byte("test"))
		temp, err := ReadBytesToWriter(&buf, &output, false)
		if err != nil || temp != 4100 {
			b.Error(err)
			return
		}
	}
}
