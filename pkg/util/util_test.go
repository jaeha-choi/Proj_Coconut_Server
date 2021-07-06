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
	// Create reader for destination file
	dstFileN := "cat_result.jpg"
	destFileNSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(len(dstFileN))))
	destFileNReader := bytes.NewReader([]byte(dstFileN))

	// Create reader for source file
	srcFileN := "../testdata/util/cat.jpg"

	srcFileReader, err := os.Open(srcFileN)
	if srcFileReader == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := srcFileReader.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	srcFileStat, err := srcFileReader.Stat()
	if srcFileStat == nil || err != nil {
		t.Error("Error while getting image file stats")
		return // imgFileStat == nil
	}
	srcFileSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(srcFileStat.Size())))

	// Combine all readers
	readers := io.MultiReader(destFileNSizeReader, destFileNReader, srcFileSizeReader, srcFileReader)

	err = ReadBinary(readers)

	if err != nil {
		t.Error("Error in ReadBinary")
	}

	// Open result image
	resImgFile, err := os.Open(filepath.Join(downloadPath, dstFileN))
	if resImgFile == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := resImgFile.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	// Reset reader offset since the file was already read once
	_, err = srcFileReader.Seek(0, 0)
	if err != nil {
		t.Error("Error while resetting reader offset")
	}

	if !ChecksumMatch(t, srcFileReader, resImgFile) {
		t.Error("Checksum does not match")
	}
	// Remove downloadPath after testing
	if err := os.RemoveAll(downloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}

func TestReadBinaryEmptyFileNSizeError(t *testing.T) {
	// Use super long text for file name
	dstFileNFile := "../testdata/util/test_8192.txt"
	fileNFile, err := os.Open(dstFileNFile)
	if err != nil {
		t.Error("Cannot read the input file")
	}
	// Close file when done
	defer func() {
		if err = fileNFile.Close(); err != nil {
			t.Error("Input file not properly closed")
		}
	}()
	fileNFileSizeReader := bytes.NewReader(sizeToBytesHelper(t, 8192))

	// Combine all readers
	readers := io.MultiReader(fileNFileSizeReader, fileNFile)

	err = ReadBinary(readers)

	if err == nil {
		t.Error("Expected error, but no error was raised.")
	}

	// Remove downloadPath after testing
	if err := os.RemoveAll(downloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}

func TestReadBinaryEmptyFileNError(t *testing.T) {
	// Create reader for destination file
	dstFileN := ""
	destFileNSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(len(dstFileN))))
	destFileNReader := bytes.NewReader([]byte(dstFileN))

	// Create reader for source file
	srcFileN := "../testdata/util/cat.jpg"

	srcFileReader, err := os.Open(srcFileN)
	if srcFileReader == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := srcFileReader.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	srcFileStat, err := srcFileReader.Stat()
	if srcFileStat == nil || err != nil {
		t.Error("Error while getting image file stats")
		return // imgFileStat == nil
	}
	srcFileSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(srcFileStat.Size())))

	// Combine all readers
	readers := io.MultiReader(destFileNSizeReader, destFileNReader, srcFileSizeReader, srcFileReader)

	err = ReadBinary(readers)

	if err == nil {
		t.Error("Expected error, but no error was raised.")
	}

	// Remove downloadPath after testing
	if err := os.RemoveAll(downloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}

func TestReadBinaryIncorrectFileSize(t *testing.T) {
	// Create reader for destination file
	dstFileN := "cat_result.jpg"
	destFileNSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(len(dstFileN))))
	destFileNReader := bytes.NewReader([]byte(dstFileN))

	// Create reader for source file
	srcFileN := "../testdata/util/cat.jpg"

	srcFileReader, err := os.Open(srcFileN)
	if srcFileReader == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := srcFileReader.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	incorrectFileSize := make([]byte, 2)
	srcFileSizeReader := bytes.NewReader(incorrectFileSize)

	// Combine all readers
	readers := io.MultiReader(destFileNSizeReader, destFileNReader, srcFileSizeReader)

	err = ReadBinary(readers)

	if err == nil {
		t.Error("Expected error, but no error was raised.")
	}

	// Remove downloadPath after testing
	if err := os.RemoveAll(downloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}

func TestReadBinaryShortReader(t *testing.T) {
	// Create reader for destination file
	dstFileN := "cat_result.jpg"
	destFileNSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(len(dstFileN))))
	destFileNReader := bytes.NewReader([]byte(dstFileN))

	// Create reader for source file
	srcFileN := "../testdata/util/cat.jpg"

	srcFileReader, err := os.Open(srcFileN)
	if srcFileReader == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := srcFileReader.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	srcFileStat, err := srcFileReader.Stat()
	if srcFileStat == nil || err != nil {
		t.Error("Error while getting image file stats")
		return // imgFileStat == nil
	}
	srcFileSizeReader := bytes.NewReader(sizeToBytesHelper(t, uint32(srcFileStat.Size())))

	limitedFile := io.LimitReader(srcFileReader, srcFileStat.Size()-100)
	// Combine all readers
	readers := io.MultiReader(destFileNSizeReader, destFileNReader, srcFileSizeReader, limitedFile)

	err = ReadBinary(readers)

	if err == nil {
		t.Error("Expected error, but no error was raised.")
	}

	// Remove downloadPath after testing
	if err := os.RemoveAll(downloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}

func TestReadWriteString(t *testing.T) {
	var buffer bytes.Buffer
	msg := "test msg"

	// Test WriteString
	writtenLen, err := WriteString(&buffer, msg)
	if writtenLen != len(msg) || err != nil {
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
		t.Error("Result does mismatch")
		return
	}
}

func TestWriteString(t *testing.T) {
	var buffer bytes.Buffer
	msg := "test msg"
	writtenLen, err := WriteString(&buffer, msg)
	if writtenLen != len(msg) || err != nil {
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
		t.Error("Size does not match")
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
		t.Error("Result does mismatch")
		return
	}
}

func TestReadNBinary(t *testing.T) {
	testFileN := "../testdata/util/cat.jpg"
	resultFileN := "cat_result.jpg"

	// Open original image
	imgFile, err := os.Open(testFileN)
	if imgFile == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := imgFile.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	imgFileStat, err := imgFile.Stat()
	if imgFileStat == nil || err != nil {
		t.Error("Error while getting image file stats")
		return // imgFileStat == nil
	}

	err = readNBinary(imgFile, uint32(imgFileStat.Size()), resultFileN)
	if err != nil {
		t.Error("Error encountered while reading binary")
	}

	// Open result image
	resImgFile, err := os.Open(filepath.Join(downloadPath, resultFileN))
	if resImgFile == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := resImgFile.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	// Reset reader offset since the file was already read once
	_, err = imgFile.Seek(0, 0)
	if err != nil {
		t.Error("Error while resetting reader offset")
	}

	if !ChecksumMatch(t, imgFile, resImgFile) {
		t.Error("Checksum does not match")
	}
	// Remove downloadPath after testing
	if err := os.RemoveAll(downloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}

func TestReadNBinaryTiny(t *testing.T) {
	testFileN := "../testdata/util/pine_cone.jpg"
	resultFileN := "pine_cone_result.jpg"

	// Open original image
	imgFile, err := os.Open(testFileN)
	if imgFile == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := imgFile.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	imgFileStat, err := imgFile.Stat()
	if imgFileStat == nil || err != nil {
		t.Error("Error while getting image file stats")
		return // imgFileStat == nil
	}

	err = readNBinary(imgFile, uint32(imgFileStat.Size()), resultFileN)
	if err != nil {
		t.Error("Error encountered while reading binary")
	}

	// Open result image
	resImgFile, err := os.Open(filepath.Join(downloadPath, resultFileN))
	if resImgFile == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := resImgFile.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	// Reset reader offset since the file was already read once
	_, err = imgFile.Seek(0, 0)
	if err != nil {
		t.Error("Error while resetting reader offset")
	}

	if !ChecksumMatch(t, imgFile, resImgFile) {
		t.Error("Checksum does not match")
	}
	// Remove downloadPath after testing
	if err := os.RemoveAll(downloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}

func TestReadWriteBinary(t *testing.T) {
	srcFileN := "../testdata/util/cat.jpg"
	var buffer bytes.Buffer

	// Test WriteBinary
	if _, err := WriteBinary(&buffer, srcFileN); err != nil {
		log.Debug(err)
		t.Error("Error in WriteBinary")
		return
	}

	// Test ReadBinary
	if err := ReadBinary(&buffer); err != nil {
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
	result, err := os.Open(filepath.Join(downloadPath, "cat.jpg"))
	if err != nil {
		log.Debug(err)
		t.Error("Error while opening dst file")
		return
	}

	// Compare checksum
	if !ChecksumMatch(t, expected, result) {
		t.Error("Checksum mismatch")
	}
}

func TestReadNBinaryCreateDirError(t *testing.T) {
	testFileN := "../testdata/util/cat.jpg"
	resultFileN := "cat_result.jpg"

	if err := os.RemoveAll(downloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}

	// Open original image
	imgFile, err := os.Open(testFileN)
	if imgFile == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := imgFile.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	imgFileStat, err := imgFile.Stat()
	if imgFileStat == nil || err != nil {
		t.Error("Error while getting image file stats")
		return // imgFileStat == nil
	}

	// Create new file to prevent downloaded directory from being created
	newFileN := downloadPath
	newFile, err := os.Create(newFileN)
	if newFile == nil || err != nil {
		log.Debug(err)
		t.Error("Error while creating a file")
		return // newFile != nil
	}
	if err := newFile.Close(); err != nil {
		t.Error("Error while creating a file")
	}

	err = readNBinary(imgFile, uint32(imgFileStat.Size()), resultFileN)
	if err == nil {
		t.Error("Expected error while readNBinary, but no error was raised.")
	}
	// Remove downloadPath after testing
	if err := os.RemoveAll(downloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}

func TestReadNBinaryTinyWrongSize(t *testing.T) {
	testFileN := "../testdata/util/pine_cone.jpg"
	resultFileN := "pine_cone_result.jpg"

	// Open original image
	imgFile, err := os.Open(testFileN)
	if imgFile == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := imgFile.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	imgFileStat, err := imgFile.Stat()
	if imgFileStat == nil || err != nil {
		t.Error("Error while getting image file stats")
		return // imgFileStat == nil
	}

	err = readNBinary(imgFile, uint32(imgFileStat.Size()+1), resultFileN)
	if err == nil {
		t.Error("Expected error, but no error was raised.")
	}
	// Remove downloadPath after testing
	if err := os.RemoveAll(downloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}

func TestReadNBinaryTinyWrongSize2(t *testing.T) {
	testFileN := "../testdata/util/cat.jpg"
	resultFileN := "cat_result.jpg"

	// Open original image
	imgFile, err := os.Open(testFileN)
	if imgFile == nil || err != nil {
		t.Error("Error opening image file")
		return // imgFile == nil
	}
	defer func() {
		if err := imgFile.Close(); err != nil {
			t.Error("Error while closing image file")
		}
	}()

	// To get the size of the input image
	imgFileStat, err := imgFile.Stat()
	if imgFileStat == nil || err != nil {
		t.Error("Error while getting image file stats")
		return // imgFileStat == nil
	}
	log.Debug(imgFileStat.Size())
	partial := io.LimitReader(imgFile, 51283)
	err = readNBinary(partial, uint32(imgFileStat.Size()), resultFileN)
	if err == nil {
		t.Error("Expected error, but no error was raised.")
	}
	// Remove downloadPath after testing
	if err := os.RemoveAll(downloadPath); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}

func TestReadString(t *testing.T) {
	testStr := "test this"

	sizeBytes := sizeToBytesHelper(t, uint32(len(testStr)))
	sizeReader := bytes.NewReader(sizeBytes)
	strReader := bytes.NewReader([]byte(testStr))
	reader := io.MultiReader(sizeReader, strReader)

	resultStr, err := ReadString(reader)
	if resultStr != testStr || err != nil {
		log.Debug("Result: ", resultStr)
		log.Debug("Expected: ", testStr)
		t.Error("Read string returned incorrect result")
	}
}

func TestReadStringSizeError(t *testing.T) {
	sizeBytes := make([]byte, 2)
	sizeReader := bytes.NewReader(sizeBytes)
	_, err := ReadString(sizeReader)
	if err == nil {
		t.Error("Expected error when reading size, but no error raised.")
	}
}

func TestReadStringSizeMax(t *testing.T) {
	// Open input file for testing
	file, err := os.Open("../testdata/util/test_4096.txt")
	if err != nil {
		t.Error("Cannot read the input file")
	}

	// Close file when done
	defer func() {
		if err = file.Close(); err != nil {
			t.Error("Input file not properly closed")
		}
	}()

	sizeReader := bytes.NewReader(sizeToBytesHelper(t, 4096))
	reader := io.MultiReader(sizeReader, file)

	result, err := ReadString(reader)
	if err != nil {
		t.Error("Error while reading string")
	}

	// Reset reader offset since the file was already read once
	_, err = file.Seek(0, 0)
	if err != nil {
		t.Error("Error while resetting reader offset")
	}

	// Read input file as string
	input, err := io.ReadAll(reader)
	if err != nil {
		t.Error("Error while reading from input file")
	}

	if string(input) != result {
		log.Debug(string(input))
		log.Debug("----------------")
		log.Debug(result)
		t.Error("Result does not match input")
	}
}

func TestReadStringSizeExceedMax(t *testing.T) {
	// Open input file for testing
	file, err := os.Open("../testdata/util/test_8192.txt")
	if err != nil {
		t.Error("Cannot read the input file")
	}

	// Close file when done
	defer func() {
		if err = file.Close(); err != nil {
			t.Error("Input file not properly closed")
		}
	}()
	sizeReader := bytes.NewReader(sizeToBytesHelper(t, 8192))
	reader := io.MultiReader(sizeReader, file)

	_, err = ReadString(reader)
	if err == nil {
		t.Error("Expected error, but no error raised.")
	}
}

func TestReadStringSizeShortReader(t *testing.T) {
	testStr := "test this"

	sizeBytes := sizeToBytesHelper(t, 1024)
	sizeReader := bytes.NewReader(sizeBytes)
	strReader := bytes.NewReader([]byte(testStr))
	reader := io.MultiReader(sizeReader, strReader)

	result, err := ReadString(reader)
	if result != "" || err == nil {
		t.Error("Expected error, but no error raised.")
	}
}

func TestReadSizeError(t *testing.T) {
	inputBytes := make([]byte, 2)
	// [0 0]
	reader := bytes.NewReader(inputBytes)
	result, err := readSize(reader)
	if result != 0 || err == nil {
		t.Error("Expected error, but no error raised.")
	}
}

func TestReadSize0(t *testing.T) {
	inputBytes := make([]byte, 4)
	// [0 0 0 0]
	reader := bytes.NewReader(inputBytes)
	result, err := readSize(reader)
	if result != 0 || err != nil {
		t.Error("Error while reading size [0]")
	}
}

func TestReadSize255(t *testing.T) {
	inputBytes := make([]byte, 4)
	// [0 0 0 255]
	inputBytes[3] = 255
	reader := bytes.NewReader(inputBytes)
	result, err := readSize(reader)
	if result != 255 || err != nil {
		t.Error("Error while reading size [255]")
	}
}

func TestReadSize4095(t *testing.T) {
	inputBytes := make([]byte, 4)
	// [0 0 15 255]
	inputBytes[2] = 15
	inputBytes[3] = 255
	reader := bytes.NewReader(inputBytes)
	result, err := readSize(reader)
	if result != 4095 || err != nil {
		t.Error("Error while reading size [4095]")
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
	result, err := readSize(reader)
	if result != uint32Max || err != nil {
		t.Error("Error while reading size uint32max")
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
	}
}

func TestReadNString(t *testing.T) {
	reader := strings.NewReader("init 1234 prev 5678 curr next \n")
	s, _ := readNString(reader, 22)
	if s != "init 1234 prev 5678 cu" {
		t.Error("Incorrect result.")
	}
}

func TestReadNStringBufferSize(t *testing.T) {
	// Open input file for testing
	file, err := os.Open("../testdata/util/test_4096.txt")
	if err != nil {
		t.Error("Cannot read the input file")
	}

	// Close file when done
	defer func() {
		if file != nil {
			if err = file.Close(); err != nil {
				t.Error("Input file not properly closed")
			}
		}
	}()

	// Test readNString
	reader := bufio.NewReader(file)
	s, err := readNString(reader, 4096)
	if err != nil {
		t.Error("readNString returned error")
	}

	// Create temp file
	tmpFile, err := ioutil.TempFile("", "tmp")
	if err != nil {
		t.Error("Error while creating temp file")
	}

	// Close and delete temp file when done
	defer func(name string) {
		if err := tmpFile.Close(); err != nil {
			t.Error("Temp file not closed.")
		}
		// Disable this statement to prevent the program from deleting
		// the file after testing
		if err := os.Remove(name); err != nil {
			log.Info("Temp file: ", name)
			t.Error("Temp file not removed.")
		}
	}(tmpFile.Name())

	// Write to tmp file for debugging
	if _, err := tmpFile.WriteString(s); err != nil {
		t.Error("Error while writing output file.")
	}

	// To guarantee the file to be written on disk before comparing
	if err = tmpFile.Sync(); err != nil {
		t.Error("File not written to disk")
	}

	// Reset reader offset since the file was already read once
	_, err = file.Seek(0, 0)
	if err != nil {
		t.Error("Error while resetting reader offset")
	}

	// Reset reader offset since the file was already read once
	_, err = tmpFile.Seek(0, 0)
	if err != nil {
		t.Error("Error while setting reader offset")
	}

	if !ChecksumMatch(t, file, tmpFile) {
		t.Error("checksum does not match")
	}
}

func TestReadNStringMaxSizePlugOne(t *testing.T) {
	// Open input file for testing
	file, err := os.Open("../testdata/util/test_4096.txt")
	if err != nil {
		t.Error("Cannot read the input file")
	}

	// Close file when done
	defer func() {
		if file != nil {
			if err = file.Close(); err != nil {
				t.Error("Input file not properly closed")
			}
		}
	}()

	// Reset reader offset since the file was already read once
	_, err = file.Seek(0, 0)
	if err != nil {
		t.Error("Error while resetting reader offset")
	}

	// Test readNString
	reader := bufio.NewReader(file)
	s, err := readNString(reader, 4097)
	if s != "" || err == nil {
		t.Error("Expected error, but error was not raised")
	}
}

func TestReadNStringBufferSizeMinusOne(t *testing.T) {
	// Open input file for testing
	file, err := os.Open("../testdata/util/test_4096.txt")
	if err != nil {
		t.Error("Cannot read the input file")
	}

	// Close file when done
	defer func() {
		if file != nil {
			if err = file.Close(); err != nil {
				t.Error("Input file not properly closed")
			}
		}
	}()

	// Test readNString
	reader := bufio.NewReader(file)
	s, _ := readNString(reader, 4095)

	tmpReader := strings.NewReader(s[:4095])

	// Reset reader offset since the file was already read once
	_, err = file.Seek(0, 0)
	if err != nil {
		t.Error("Error while resetting reader offset")
	}
	inputReader := io.LimitReader(file, 4095)

	if !ChecksumMatch(t, inputReader, tmpReader) {
		t.Error("checksum does not match")
	}
}

func TestReadNStringZero(t *testing.T) {
	reader := strings.NewReader("init 1234 prev 5678 curr next \n")
	s, _ := readNString(reader, 0)
	if s != "" {
		t.Error("Incorrect result.")
	}
}

func TestReadNStringExceed(t *testing.T) {
	reader := strings.NewReader("init 1234 prev 5678 curr next \n")
	_, err := readNString(reader, 50)
	if err == nil {
		t.Error("Expected error, but no error raised.")
	}
}

func TestIntToUint32SignedInt(t *testing.T) {
	val, err := IntToUint32(-1)
	if val != 0 || err == nil {
		t.Error("Expected error, but no error raised.")
	}
}

func TestIntToUint32Max(t *testing.T) {
	val, err := IntToUint32(4294967296)
	if val != 0 || err == nil {
		t.Error("Expected error, but no error raised.")
	}
}

func TestIntToUint32(t *testing.T) {
	val, err := IntToUint32(27532)
	if val != 27532 || err != nil {
		t.Error("Error during conversion")
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
		t.Error("Error while getting sha1sum for 'expected' reader")
	}
	f1Hash := fmt.Sprintf("%x", h.Sum(nil))
	log.Info("Expected sha1sum: ", f1Hash)

	// Get sha-1 sum of result
	h2 := sha1.New()
	if _, err := io.Copy(h2, result); err != nil {
		t.Error("Error while getting sha1sum for 'result' reader")
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
	}
}

func TestCheckIPAddressInvalidIpv4(t *testing.T) {
	invalidIPV4 := "1000.40.210.253"
	if CheckIPAddress(invalidIPV4) {
		t.Error("TestCheckIPAddressInvalidIpv4 is invalid")
	}
}

func TestCheckIPAddressValidIpv6(t *testing.T) {
	validIPV6 := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	if !CheckIPAddress(validIPV6) {
		t.Error("TestCheckIPAddressValidIpv6 is invalid")
	}
}

func TestCheckIPAddressInvalidIpv6(t *testing.T) {
	invalidIPV6 := "2001:0db8:85a3:0000:0000:8a2e:0370:7334:3445"
	if CheckIPAddress(invalidIPV6) {
		t.Error("TestCheckIPAddressInvalidIpv6 is invalid")
	}
}
