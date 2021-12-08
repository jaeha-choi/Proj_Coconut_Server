package util

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/jaeha-choi/Proj_Coconut_Utility/common"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"gopkg.in/yaml.v3"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	HeaderSize   = 6
	BufferSize   = 4096
	Uint32Max    = 4294967295
	DownloadPath = "./downloaded"
)

type Message struct {
	Data        []byte
	ErrorCode   uint8
	CommandCode uint8
}

type UDPMessage struct {
	Data        []byte
	Sequence    uint32
	Total       uint32
	ErrorCode   uint8
	CommandCode uint8
}

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, BufferSize)
		return b
	},
}

// ReadMessage reads message from reader.
func ReadMessage(reader io.Reader) (msg *Message, err error) {
	// Read packet size
	size, err := readSize(reader)
	if err != nil {
		return nil, err
	}

	// Read Error Code
	header, err := readNBytes(reader, 2)
	if err != nil {
		return nil, err
	}

	// Create new Message
	msg = &Message{
		Data:        nil,
		ErrorCode:   header[0],
		CommandCode: header[1],
	}

	// Read data
	msg.Data, err = readNBytes(reader, size)
	return msg, err
}

func ReadMessageUDP(reader *net.UDPConn) (msg *Message, addr *net.UDPAddr, err error) {
	// Read packet into buffer
	buffer := make([]byte, BufferSize)
	_, addr, err = reader.ReadFromUDP(buffer)
	if err != nil {
		return nil, nil, err
	}
	size := binary.BigEndian.Uint32(buffer[0:4])
	errorCode := buffer[4]
	commandCode := buffer[5]

	// Create new Message
	msg = &Message{
		Data:        buffer[6 : size+6],
		ErrorCode:   errorCode,
		CommandCode: commandCode,
	}
	return msg, addr, err
}

func ReadFilePacketUDP(writer *net.UDPConn) (msg *UDPMessage, err error) {
	buffer := make([]byte, BufferSize)
	n, _, err := writer.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}
	sequence := binary.BigEndian.Uint32(buffer[0:4])
	total := binary.BigEndian.Uint32(buffer[4:8])
	errCode := buffer[8]
	commandCode := buffer[9]
	data := buffer[10:n]
	buffer = make([]byte, BufferSize)
	return &UDPMessage{
		Data:        data,
		Sequence:    sequence,
		Total:       total,
		ErrorCode:   errCode,
		CommandCode: commandCode,
	}, nil
}

// ReadFileUDP reads a packet from reader, then continues reading packets and creating the file under
// ReadFileUDP returns a pointer to the prewritten file, the number of packets read, the address of peer and error if applicable
// file name must be specified before call
// timeouts may occur depending on file size being read
func ReadFileUDP(reader *net.UDPConn, fileName string) (file *os.File, n int, addr *net.UDPAddr, err error) {
	// verify filename does not include path
	fileName = filepath.Base(fileName)
	// set timeout deadline to 10 seconds
	err = reader.SetReadDeadline(time.Now().Add(20 * time.Second))
	if err != nil {
		log.Error("Error setting up read deadline")
		return nil, 0, nil, err
	}

	// create necessary buffers and maps
	// store read packets to be reordered
	packets := make(map[uint32][]byte)
	// general acknowledgment buffer
	ackBuffer := make([]byte, 10)
	// general data buffer
	buffer := make([]byte, BufferSize)
	// map for acknowledgment messages
	// read first packet
	n, addr, err = reader.ReadFromUDP(buffer)
	if err != nil {
		log.Error("Error reading from peer")
		return nil, 0, nil, err
	}
	// get sequence number
	packetNum := binary.BigEndian.Uint32(buffer[0:4])
	// add packet to packet map
	packets[packetNum] = buffer[10:n]
	// write sequence number to acknowledgment header
	//binary.BigEndian.PutUint32(ackBuffer[0:4], packetNum)
	// get number of total packets
	total := binary.BigEndian.Uint32(buffer[4:8])
	// write total number to acknowledgment header
	//binary.BigEndian.PutUint32(ackBuffer[4:8], total)
	// preserver error and command codes
	//ackBuffer[8] = buffer[8]
	//ackBuffer[9] = buffer[9]
	// set acknowledgment number to true
	// set ackBuffer to header in buffer
	ackBuffer = buffer[:10]
	// write acknowledgment back to peer
	_, err = reader.WriteTo(ackBuffer, addr)
	if err != nil {
		log.Error("Error writing to peer")
		return nil, 0, nil, err
	}
	i := uint32(1)
	for uint32(len(packets)) < total {
		// clear buffer
		buffer := make([]byte, BufferSize)
		// reset deadline
		err = reader.SetReadDeadline(time.Now().Add(20 * time.Second))
		if err != nil {
			return nil, 0, nil, err
		}
		// read next packet from peer
		n, _, err := reader.ReadFromUDP(buffer)
		if err != nil {
			log.Error(err)
			log.Error("Error reading from peer")
			return nil, 0, nil, common.TimeoutError
		}
		ackBuffer = buffer[:10]
		// 	Preserve Header
		// get sequence number
		packetNum := binary.BigEndian.Uint32(buffer[0:4])
		//// add packet to packet map
		packets[packetNum] = buffer[10:n]
		// write acknowledgment
		_, err = reader.WriteTo(ackBuffer, addr)
		if err != nil {
			log.Error("Error writing to peer")
			return nil, 0, nil, err
		}
		i++
	}
	binary.BigEndian.PutUint32(ackBuffer[0:4], Uint32Max)
	reader.WriteTo(ackBuffer, addr)
	// verify all packets were received
	i = 0
	for i < total {
		if _, ok := packets[i]; !ok {
			log.Error("Packet ", i, " missing")
			return nil, 0, nil, common.TaskNotCompleteError
		}
		i++
	}
	// open file to write
	file, err = os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		log.Error(err)
	}
	// write packets in order
	i = 0
	for i < total {
		_, err := file.Write(packets[i])
		if err != nil {
			return nil, 0, nil, err
		}
		i++
	}
	return file, int(i), addr, err
}

// WriteMessage write msg to writer. commandToWrite should not be nil
// Returns int indicating the number of bytes written, and error, if any.
// err == nil only if length of sent bytes = length of msg
func WriteMessage(writer io.Writer, b []byte, errorToWrite *common.Error, commandToWrite *common.Command) (n int, err error) {
	//// Return error if b is too big
	//if len(b) > BufferSize {
	//	log.Error("Byte should contain less than ", BufferSize)
	//	return 0, SizeError
	//}

	// Check b len
	size, err := IntToUint32(len(b))
	if err != nil {
		return 0, err
	}

	// Get error errCode
	var errCode uint8 = 0
	if errorToWrite != nil {
		errCode = errorToWrite.ErrCode
	}

	// Create header
	// First 4 bytes: size
	// 5th byte: error code
	// 6th byte: command
	header := createHeader(size)
	header[4] = errCode
	header[5] = commandToWrite.Code

	// Write b to writer
	writtenSize, err := writer.Write(append(header, b...))
	if err != nil {
		return writtenSize, err
	}
	return writtenSize, err
}

// WriteMessageUDP write msg to UDP Address. commandToWrite should not be nil
// Returns int indicating the number of bytes written, and error, if any.
// err == nil only if length of sent bytes = length of msg
func WriteMessageUDP(writer *net.UDPConn, address *net.UDPAddr, b []byte, errorToWrite *common.Error, commandToWrite *common.Command) (n int, err error) {
	//// Return error if b is too big
	//if len(b) > BufferSize {
	//	log.Error("Byte should contain less than ", BufferSize)
	//	return 0, SizeError
	//}

	// Check b len
	size, err := IntToUint32(len(b))
	if err != nil {
		return 0, err
	}

	// Get error errCode
	var errCode uint8 = 0
	if errorToWrite != nil {
		errCode = errorToWrite.ErrCode
	}

	// Create header
	// First 4 bytes: size
	// 5th byte: error code
	// 6th byte: command
	header := createHeader(size)
	header[4] = errCode
	header[5] = commandToWrite.Code

	// Write b to writer
	writtenSize, err := writer.WriteTo(append(header, b...), address)
	if err != nil {
		return writtenSize, err
	}
	return writtenSize, err
}

// WriteFileUDP writes a file stored in b to UDP Address
// File is divided into multiple parts if file is too larges and acknowledgment
// packets are expected from receiver
// Due to WriteFileUDP using writer as both a writer and a reader,
// command handler must be paused before call to function
func WriteFileUDP(writer *net.UDPConn, reader *net.UDPAddr, b []byte, errorToWrite *common.Error, commandToWrite *common.Command) (n int, err error) {
	// get number of packets to be sent
	packets := make(map[uint32][]byte)
	t := float64(len(b)) / float64(BufferSize-10)
	totalPackets := uint32(math.Ceil(t))
	total := make([]byte, 4)
	binary.BigEndian.PutUint32(total, totalPackets)
	// create general buffer with hardcoded error and command
	// bytes 0:4 : sequence number
	// bytes 4:8 : totalPackets
	// byte 8	 : error code
	// byte 9	 : command code
	var errCode uint8 = 0
	if errorToWrite != nil {
		errCode = errorToWrite.ErrCode
	}
	var commandCode uint8 = 0
	if commandToWrite != nil {
		commandCode = commandToWrite.Code
	}
	header := make([]byte, 10)
	// set start and end point for data to be sent excluding 10 bytes for header
	totalSent := make(chan int)
	returnErr := make(chan error)
	go func() {
		var bufferStart = 0
		// BUFFERSIZE - 10 BECAUSE HEADER IS 10 BYTES OF EVERY PACKET
		var bufferEnd = BufferSize - 10
		var i uint32 = 0
		// write all packets to writer
		for i < totalPackets {
			if bufferStart+BufferSize-10 >= len(b) {
				bufferEnd = len(b)
			}
			// set sequence number in header
			binary.BigEndian.PutUint32(header[0:4], i)
			// set total packet number in header
			binary.BigEndian.PutUint32(header[4:8], totalPackets)
			// preserve errorCode and commandCode
			header[8] = errCode
			header[9] = commandCode
			// append header to data buffer
			buffer := append(header, b[bufferStart:bufferEnd]...)
			// edit data start and end
			bufferStart += BufferSize - 10
			bufferEnd += BufferSize - 10
			// write buffer to peer
			_, err := writer.WriteTo(buffer, reader)
			if err != nil {
				log.Error("Error writing file peer")
				totalSent <- int(i)
				returnErr <- err
				//return int(i), err
			}
			// write packet to packet map in case it needs to be resent
			packets[i] = buffer
			i++
		}
	}()
	go func() {
		//
		// NOW READING ACKNOWLEDGMENTS/RESENDING PACKETS
		// create acknowledgment map
		acksReceived := make(map[uint32]bool)
		var index uint32
		timeouts := 0
		for {
			if uint32(len(acksReceived)) == totalPackets {
				totalSent <- int(totalPackets)
				returnErr <- nil
				//return int(totalPackets), nil
			}
			// set deadline to allow for up to 10 seconds for a response
			err := writer.SetReadDeadline(time.Now().Add(15 * time.Second))
			if err != nil {
				totalSent <- 0
				returnErr <- err
				//return 0, err
			}
			ackBuffer := make([]byte, 10)
			// read acknowledgements into buffer
			// (packets should contain no data, thus only a 10 byte header)
			_, addr, err := writer.ReadFromUDP(ackBuffer)

			//log.Debug(ackBuffer)
			if err != nil {
				// check if all packets received first
				log.Debug("Total Acknowledgments Received: ", len(acksReceived))
				if uint32(len(acksReceived)) == totalPackets {
					totalSent <- int(totalPackets)
					returnErr <- nil
					//return int(totalPackets), nil
				}
				// timeout occurred
				log.Error(err)
				timeouts += 1
				// check how many timeout have occurred
				if timeouts > 10 {
					totalSent <- 0
					returnErr <- common.TimeoutError
					//return 0, common.TimeoutError
				}
				// if timeout occurs, rewrite all unacknowledged packets back to peer
				var j uint32 = 0
				// check what packets haven't been acknowledged
				for j < totalPackets {
					if _, ok := acksReceived[j]; !ok {
						// rewrite unacknowledged packet
						_, err = writer.WriteTo(packets[j], reader)
					}
					j++
				}
			}
			// if received address does not match sent address, do nothing

			if sqc := binary.BigEndian.Uint32(ackBuffer[0:4]); sqc == Uint32Max {
				totalSent <- int(totalPackets)
				returnErr <- nil
			}
			if addr.String() != reader.String() {
				continue
			}
			// log receiving of acknowledgment packet
			index = binary.BigEndian.Uint32(ackBuffer[0:4])
			// set ack to received
			acksReceived[index] = true
			// check if length of ack is the same length as packets (if true, all packets acknowledged)
		}
	}()
	packetsSent := <-totalSent
	returnError := <-returnErr
	return packetsSent, returnError
}

// readSize reads first 4 bytes from the reader and convert them into a uint32 value
func readSize(reader io.Reader) (uint32, error) {
	// Read first 4 bytes for the size
	b, err := readNBytes(reader, 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// Uint32ToByte converts uint32 value to byte slices
func Uint32ToByte(size uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, size)
	return b
}

// createHeader creates header and write size
func createHeader(size uint32) []byte {
	b := make([]byte, HeaderSize)
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

// Int64ToUint32 converts int64 value to uint32.
// Returns value and error. If value occurs overflow, 0 and error is returned
func Int64ToUint32(n int64) (uint32, error) {
	if n < 0 || n > Uint32Max {
		log.Error("value ", n, " overflows uint32")
		return 0, errors.New("value overflows uint32")
	}
	return uint32(n), nil
}

// IntToUint32 converts int64 value to uint32.
// Returns value and error. If value occurs overflow, 0 and error is returned
func IntToUint32(n int) (uint32, error) {
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
		return err
	}

	if _, err := dstFile.Write(marshal); err != nil {
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

// ReadBytesToWriter reads message from reader and write it to writer.
// First four bytes of reader should be uint32 size of the message,
// represented in big endian.
// Common usage for this function is to read from net.Conn, and write to temp file.
func ReadBytesToWriter(reader io.Reader, writer io.Writer, writeWithHeader bool) (n int, err error) {
	return readWrite(reader, writer, writeWithHeader)
}

// readWrite is a helper function to read exactly size bytes from reader and write it to writer.
// Returns length of bytes written and error, if any. Error = nil only if length of bytes
// written = size.
// readWrite will not function as intended if writer is for dart implementation.
// This is because dart will message frame the incoming packet and treat split packets as separate packet
// Keep the size below BufferSize
func readWrite(reader io.Reader, writer io.Writer, writeWithHeader bool) (int, error) {
	totalReceived := 0
	startIdx := HeaderSize
	readSize := BufferSize
	buffer := bufPool.Get().([]byte)

	// Read header
	read, err := io.ReadFull(reader, buffer[:HeaderSize])
	if err != nil || read != HeaderSize {
		return totalReceived, err
	}
	// Assumes the first 4 bytes are size
	intSize := int(binary.BigEndian.Uint32(buffer[:HeaderSize]))

	// If writeWithHeader, overwrite header
	if !writeWithHeader {
		startIdx = 0
	}

	for totalReceived < intSize {
		if totalReceived+BufferSize > intSize {
			readSize = intSize - totalReceived
		}
		read, err := io.ReadFull(reader, buffer[startIdx:readSize])
		if err != nil || read != readSize {
			return totalReceived, err
		}
		written, err := writer.Write(buffer[:readSize])
		totalReceived += written
		if err != nil {
			return totalReceived, err
		}
		startIdx = 0
	}
	bufPool.Put(buffer)
	return totalReceived, nil
}

// ReadAckUDP waits for and reads acknowledgment of previously sent packet
// matches sequence num with incoming packet sequence num
// returns true if acknowledgment found, false if timeout occurs
// *can take up to 15 seconds to execute if timeout occurs
func ReadAckUDP(seqNum uint32, writer *net.UDPConn, address *net.UDPAddr, packet []byte) (ack bool) {
	buffer := make([]byte, 4)
	if err := writer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return false
	}
	timeoutCount := 0
	for timeoutCount < 3 {
		if _, _, err := writer.ReadFromUDP(buffer); err != nil {
			timeoutCount += 1
			if _, err = writer.WriteTo(packet, address); err != nil {
				return false
			}
		} else {
			if sqc := binary.BigEndian.Uint32(buffer); sqc == seqNum {
				return true
			}
		}
	}
	return false
}

func WriteFilePacketUDP(writer *net.UDPConn, addr *net.UDPAddr, sequence uint32, totalPackets uint32, e *common.Error, command *common.Command, data []byte) (packet []byte, err error) {
	if len(data) > BufferSize-10 {
		return nil, common.DataTooLargeError
	}

	header := make([]byte, 10)
	binary.BigEndian.PutUint32(header[0:4], sequence)
	binary.BigEndian.PutUint32(header[4:8], totalPackets)
	var errCode uint8 = 0
	if e != nil {
		errCode = e.ErrCode
	}
	var commandCode uint8 = 0
	if command != nil {
		commandCode = command.Code
	}
	header[8] = errCode
	header[9] = commandCode
	packet = append(header, data...)

	_, err = writer.WriteTo(packet, addr)
	return packet, err
}
