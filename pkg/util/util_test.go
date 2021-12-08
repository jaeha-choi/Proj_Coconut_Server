package util

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"github.com/jaeha-choi/Proj_Coconut_Utility/common"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func init() {
	log.Init(os.Stdout, log.DEBUG)
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

// TODO: Fix or remove outdated test cases
//func TestReadNStringBufferSize(t *testing.T) {
//	// Open input file for testing
//	file, err := os.Open("../testdata/test_4096.txt")
//	if err != nil {
//		log.Debug(err)
//		t.Error("Cannot read the input file")
//		return
//	}
//
//	// Close file when done
//	defer func() {
//		if file != nil {
//			if err := file.Close(); err != nil {
//				log.Debug(err)
//				t.Error("Input file not properly closed")
//			}
//		}
//	}()
//
//	// Test readNString
//	reader := bufio.NewReader(file)
//	s, err := readNString(reader, 4096)
//	if err != nil {
//		log.Debug(err)
//		t.Error("readNString returned error")
//		return
//	}
//
//	// Create temp file
//	tmpFile, err := ioutil.TempFile("", "tmp")
//	if err != nil {
//		log.Debug(err)
//		t.Error("Error while creating temp file")
//		return
//	}
//
//	// Close and delete temp file when done
//	defer func(name string) {
//		if err := tmpFile.Close(); err != nil {
//			log.Debug(err)
//			t.Error("Temp file not closed.")
//		}
//		// Disable this statement to prevent the program from deleting
//		// the file after testing
//		if err := os.Remove(name); err != nil {
//			log.Debug(err)
//			log.Info("Temp file: ", name)
//			t.Error("Temp file not removed.")
//		}
//	}(tmpFile.Name())
//
//	// Write to tmp file for debugging
//	if _, err := tmpFile.WriteString(s); err != nil {
//		log.Debug(err)
//		t.Error("Error while writing output file.")
//		return
//	}
//
//	// To guarantee the file to be written on disk before comparing
//	if err := tmpFile.Sync(); err != nil {
//		log.Debug(err)
//		t.Error("File not written to disk")
//		return
//	}
//
//	// Reset reader offset since the file was already read once
//	if _, err := file.Seek(0, 0); err != nil {
//		log.Debug(err)
//		t.Error("Error while resetting reader offset")
//		return
//	}
//
//	// Reset reader offset since the file was already read once
//	if _, err := tmpFile.Seek(0, 0); err != nil {
//		log.Debug(err)
//		t.Error("Error while setting reader offset")
//		return
//	}
//
//	if !ChecksumMatch(t, file, tmpFile) {
//		t.Error("checksum does not match")
//		return
//	}
//}

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
	if val, err := Int64ToUint32(-1); val != 0 || err == nil {
		t.Error("Expected error, but no error raised.")
		return
	}
}

func TestIntToUint32Max(t *testing.T) {
	if val, err := Int64ToUint32(4294967296); val != 0 || err == nil {
		t.Error("Expected error, but no error raised.")
		return
	}
}

func TestIntToUint32(t *testing.T) {
	if val, err := Int64ToUint32(27532); val != 27532 || err != nil {
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

func TestWriteFileUDP(t *testing.T) {
	addr := "127.0.0.1:12345"
	addr2 := "127.0.0.1:54321"
	address, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Error(err)
	}
	address2, err := net.ResolveUDPAddr("udp", addr2)
	if err != nil {
		t.Error(err)
	}
	UDPconn, err := net.ListenUDP("udp", address)
	if err != nil {
		t.Error(err)
	}
	UDPconn2, err := net.ListenUDP("udp", address2)
	if err != nil {
		t.Error(err)
	}
	b, err := ioutil.ReadFile("/home/duncan/Downloads/abcde_long.txt") // b has type []byte
	if err != nil {
		t.Error(err)
	}
	log.Info(len(b))
	go func() {
		n, err := WriteFileUDP(UDPconn, address2, b, common.TimeoutError, common.File)
		log.Debug("TOTAL SENT: ", n)
		if err != nil {
			t.Error(err)
		}
	}()
	time.Sleep(1 * time.Second)
	b = []byte{}
	go func() {
		returnVal := []byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0}
		buffer := make([]byte, BufferSize)
		n, _, err := UDPconn2.ReadFromUDP(buffer)
		if err != nil {
			t.Error(err)
			panic(err)
		}
		b = append(b, buffer[10:n]...)
		packetNum := binary.BigEndian.Uint32(buffer[0:4])
		binary.BigEndian.PutUint32(returnVal[0:4], packetNum)
		UDPconn2.WriteTo(returnVal, address)
		total := binary.BigEndian.Uint32(buffer[4:8])
		i := uint32(1)
		for i < total {
			_, _, err := UDPconn2.ReadFromUDP(buffer)
			if err != nil {
				t.Error(err)
			}
			b = append(b, buffer[10:n]...)
			packetNum := binary.BigEndian.Uint32(buffer[0:4])
			binary.BigEndian.PutUint32(returnVal[0:4], packetNum)
			UDPconn2.WriteTo(returnVal, address)
			i++
		}
		os.WriteFile("download.txt", b, 777)
		log.Debug("TOTAL RECEIVED: ", i)
	}()

	b, err = ioutil.ReadFile("/home/duncan/Downloads/abcd.txt") // b has type []byte
	if err != nil {
		t.Error(err)
	}
	log.Info(len(b))
	go func() {
		n, err := WriteFileUDP(UDPconn, address2, b, common.TimeoutError, common.File)
		log.Debug("TOTAL SENT: ", n)
		if err != nil {
			t.Error(err)
		}
	}()
	time.Sleep(1 * time.Second)
	b = []byte{}
	go func() {
		returnVal := []byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0}
		buffer := make([]byte, BufferSize)
		n, _, err := UDPconn2.ReadFromUDP(buffer)
		if err != nil {
			t.Error(err)
			panic(err)
		}
		b = append(b, buffer[10:n]...)
		packetNum := binary.BigEndian.Uint32(buffer[0:4])
		binary.BigEndian.PutUint32(returnVal[0:4], packetNum)
		UDPconn2.WriteTo(returnVal, address)
		total := binary.BigEndian.Uint32(buffer[4:8])
		i := uint32(1)
		for i < total {
			_, _, err := UDPconn2.ReadFromUDP(buffer)
			if err != nil {
				t.Error(err)
			}
			b = append(b, buffer[10:n]...)
			packetNum := binary.BigEndian.Uint32(buffer[0:4])
			binary.BigEndian.PutUint32(returnVal[0:4], packetNum)
			UDPconn2.WriteTo(returnVal, address)
			i++
		}
		os.WriteFile("download2.txt", b, 777)
		log.Debug("TOTAL RECEIVED: ", i)
	}()

	b, err = ioutil.ReadFile("/home/duncan/Downloads/abc.txt") // b has type []byte
	if err != nil {
		t.Error(err)
	}
	log.Info(len(b))
	go func() {
		n, err := WriteFileUDP(UDPconn, address2, b, common.TimeoutError, common.File)
		log.Debug("TOTAL SENT: ", n)
		if err != nil {
			t.Error(err)
		}
	}()
	time.Sleep(1 * time.Second)
	b = []byte{}
	go func() {
		returnVal := []byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0}
		buffer := make([]byte, BufferSize)
		n, _, err := UDPconn2.ReadFromUDP(buffer)
		if err != nil {
			t.Error(err)
			panic(err)
		}
		b = append(b, buffer[10:n]...)
		packetNum := binary.BigEndian.Uint32(buffer[0:4])
		binary.BigEndian.PutUint32(returnVal[0:4], packetNum)
		UDPconn2.WriteTo(returnVal, address)
		total := binary.BigEndian.Uint32(buffer[4:8])
		i := uint32(1)
		for i < total {
			_, _, err := UDPconn2.ReadFromUDP(buffer)
			if err != nil {
				t.Error(err)
			}
			b = append(b, buffer[10:n]...)
			packetNum := binary.BigEndian.Uint32(buffer[0:4])
			binary.BigEndian.PutUint32(returnVal[0:4], packetNum)
			UDPconn2.WriteTo(returnVal, address)
			i++
		}
		os.WriteFile("download3.txt", b, 777)
		log.Debug("TOTAL RECEIVED: ", i)
	}()
	time.Sleep(1 * time.Minute)
}

func TestReadWriteFileUDP(t *testing.T) {
	addr := "127.0.0.1:12345"
	addr2 := "127.0.0.1:54321"
	address, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Error(err)
	}
	address2, err := net.ResolveUDPAddr("udp", addr2)
	if err != nil {
		t.Error(err)
	}
	UDPconn, err := net.ListenUDP("udp", address)
	if err != nil {
		t.Error(err)
	}
	UDPconn2, err := net.ListenUDP("udp", address2)
	if err != nil {
		t.Error(err)
	}
	file := "/home/duncan/projects/Proj_Coconut_Utility/testdata/A17_FlightPlan.pdf"
	b, err := ioutil.ReadFile(file)
	log.Debug("FILE SIZE: ", ByteCountSI(int64(len(b))))
	if err != nil {
		log.Error(err)
	}
	now := time.Now()
	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		//address := &syscall.SockaddrInet4{
		//	Port: 54321,
		//	Addr: [4]byte{127,0,0,1},
		//}
		b, n, addr, err := ReadFileUDP(UDPconn2, file)
		if err != nil {
			log.Debug("TOTAL RECEIVED: ", n, " FROM: ", addr, "\nTIME: ", time.Since(now).Seconds())
			wg.Done()
			log.Error(err)
			t.Error(err)
			panic(err)
		}
		//err = os.WriteFile("download.jpg", b, 777)
		//if err != nil {
		//	log.Error(err)
		//	t.Error(err)
		//}
		err = b.Close()
		if err != nil {
			wg.Done()
			t.Error(err)
		}
		log.Debug("TOTAL RECEIVED: ", n, " FROM: ", addr, "\nTIME: ", time.Since(now).Seconds())
		wg.Done()
	}()
	time.Sleep(1 * time.Second)
	go func() {
		wg.Add(1)
		c, err := WriteFileUDP(UDPconn, address2, b, common.TimeoutError, common.File)
		if err != nil {
			wg.Done()
			log.Error(err)
			t.Error(err)
		}
		log.Debug("TOTAL SENT: ", c, "\nTIME: ", time.Since(now).Seconds())
		wg.Done()
	}()
	wg.Wait()
	totalTime := time.Since(now).Seconds()
	log.Debug("TOTAL TIME: ", totalTime)
	log.Debug(ByteCountSI(int64(float64(len(b))/totalTime)) + "s/second")

}

// used to convert bytes to KB/MB
func ByteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "KMGTPE"[exp])
}
