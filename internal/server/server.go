package server

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/jaeha-choi/Proj_Coconut_Utility/common"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"github.com/jaeha-choi/Proj_Coconut_Utility/util"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	mRand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

const (
	// keyPairName is a name for the public/private key pair (without extensions)
	keyPairName = "server"
	// addCodeArrSize is the max number for Add Code
	addCodeArrSize = 999999

	debugClientNameLen = 5
)

type client struct {
	isBeingUsed      bool
	isBeingUsedMutex *sync.Mutex
	addCodeIdx       int
	connToClient     net.Conn
	localAddr        string
	publicAddr       string
	pubKeyHash       string
	// May add Pub/Priv IP/Port for hole punching
}

// Server related configurations
type Server struct {
	Host     string `yaml:"host"`
	Port     uint16 `yaml:"port"`
	CertPath string `yaml:"cert_path"`

	addCodeArrMutex *sync.RWMutex
	// addCodeArr stores shuffled Add Code in integer with a string indicating
	// the device occupying the Add Code.
	// string != "" if the Add Code is allocated to a device, "" otherwise.
	// 000 000 is reserved for initial value, and should not be used for allocation.
	// i.e. addCodeArr[index] = [Add Code (int), pubKeyHash (string)]
	addCodeArr [addCodeArrSize][2]interface{}

	// addCodeIdx stores indices to actual Add Code (inverse of addCodeArr)
	// i.e. addCodeIdx[addCode - 1] = index to Add Code in addCodeArr
	// Requires no lock as addCodeIdx is read-only after initAddCode()
	addCodeIdx [addCodeArrSize]int

	nextAddCodeIdxMutex *sync.Mutex
	// nextAddCodeIdx represents index of next available Add Code element in addCodeArr
	nextAddCodeIdx int

	// devices stores public key hash as a key (string), *client structure as a value.
	devices sync.Map

	tls *tls.Config
}

// init initializes logger and set mRand seed
func init() {
	var seed [8]byte
	_, err := rand.Read(seed[:])
	if err != nil {
		log.Debug(err)
		log.Error("Error while setting up math/random seed")
		os.Exit(1)
		return
	}
	mRand.Seed(int64(binary.LittleEndian.Uint64(seed[:])))
}

// initAddCode initializes Add Code and shuffles them
func (serv *Server) initAddCode() {
	// No need to lock here as no other goroutine accesses these arrays yet.
	for i := 0; i < addCodeArrSize; i++ {
		serv.addCodeArr[i] = [2]interface{}{i + 1, ""}
	}
	mRand.Shuffle(addCodeArrSize, func(i, j int) {
		serv.addCodeArr[i], serv.addCodeArr[j] = serv.addCodeArr[j], serv.addCodeArr[i]
		serv.addCodeIdx[serv.addCodeArr[i][0].(int)-1] = i
		serv.addCodeIdx[serv.addCodeArr[j][0].(int)-1] = j
	})
}

// InitConfig initializes Server struct, Add Codes, and TLS configuration.
func InitConfig() (serv *Server, err error) {
	serv = &Server{
		Host:                "127.0.0.1",
		Port:                9129,
		CertPath:            "./data/cert",
		addCodeArr:          [addCodeArrSize][2]interface{}{},
		addCodeIdx:          [addCodeArrSize]int{},
		nextAddCodeIdx:      0,
		devices:             sync.Map{},
		tls:                 nil,
		addCodeArrMutex:     &sync.RWMutex{},
		nextAddCodeIdxMutex: &sync.Mutex{},
	}
	serv.initAddCode()
	if err := serv.tlsConfig(); err != nil {
		return nil, err
	}
	return serv, nil
}

// tlsConfig initializes TLS configuration
func (serv *Server) tlsConfig() (err error) {
	serv.tls = &tls.Config{
		Rand:         rand.Reader,
		Certificates: nil,
		//GetCertificate:              nil,
		//GetClientCertificate:        nil,
		//GetConfigForClient:          nil,
		//VerifyPeerCertificate:       nil,
		//VerifyConnection:            nil,
		RootCAs:    nil,
		ServerName: "127.0.0.1",
		//ClientAuth:                  0,
		//ClientCAs:                   nil,
		//InsecureSkIPVerify: false,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		//KeyLogWriter:                nil,
	}

	pair, err := tls.LoadX509KeyPair(filepath.Join(serv.CertPath, keyPairName+".crt"), filepath.Join(serv.CertPath, keyPairName+".key"))
	if err != nil {
		log.Debug(err)
		log.Error("Error while loading .crt and .key file--check if the files exist")
		return err
	}
	serv.tls.Certificates = []tls.Certificate{pair}
	return nil
}

// ReadConfig reads a config from a yaml file
func ReadConfig(fileName string) (serv *Server, err error) {
	serv, err = InitConfig()
	if err != nil {
		log.Debug(err)
		return nil, err
	}
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Debug(err)
		log.Error("Error while reading config.yml")
		return nil, err
	}
	err = yaml.Unmarshal(file, &serv)
	if err != nil {
		log.Debug(err)
		log.Error("Error while parsing config.yml")
		return nil, err
	}
	return serv, nil
}

func (serv *Server) removeDevice(pubKeyHash string) {
	// Detach Add Code from the client in case the client is still using the Add Code
	c, ok := serv.devices.Load(pubKeyHash)
	if ok && c != nil {
		cli := c.(*client)
		if cli.addCodeIdx != -1 {
			// Write lock
			serv.addCodeArrMutex.Lock()
			// Mark the Add Code as available, by setting pubKeyH field to empty string
			serv.addCodeArr[cli.addCodeIdx][1] = ""
			serv.addCodeArrMutex.Unlock()

			cli.addCodeIdx = -1
		}
	}

	// Remove device from map
	serv.devices.Delete(pubKeyHash)
}

// removeAddCode removes a device with provided Add Code from the server,
// preventing other devices from searching this device
func (serv *Server) removeAddCode(addCode int, pubKeyHash string) (err error) {
	// Find the index of Add Code with the inverse array
	addCodeIdx := serv.addCodeIdx[addCode-1]
	pubKeyH := serv.addCodeArr[addCodeIdx][1]

	// Client does not own this Add Code
	if pubKeyHash != pubKeyH {
		return common.PubKeyMismatchError
	}

	// Write lock
	serv.addCodeArrMutex.Lock()
	// Mark the Add Code as available, by setting pubKeyH field to empty string
	serv.addCodeArr[addCodeIdx][1] = ""
	serv.addCodeArrMutex.Unlock()

	// Update client struct field
	c, ok := serv.devices.Load(pubKeyHash)
	if !ok || c == nil {
		log.Debug(common.ClientNotFoundError)
		return common.ClientNotFoundError
	}
	cli := c.(*client)
	cli.addCodeIdx = -1

	// Log
	//log.Debug("removeDev//addCodeArr: ", serv.addCodeArr[addCodeIdx])
	//log.Debug(serv.devices.Load(pubKeyH))

	return nil
}

func (serv *Server) addDevice(pubKeyHash string, lAddr string, conn net.Conn) {
	newClient := &client{
		isBeingUsed:      false,
		isBeingUsedMutex: &sync.Mutex{},
		addCodeIdx:       -1,
		connToClient:     conn,
		localAddr:        lAddr,
		publicAddr:       conn.RemoteAddr().String(),
	}
	// Add device public key hash to online devices
	log.Info(newClient.localAddr)
	serv.devices.Store(pubKeyHash, newClient)
}

// getAddCode adds a device by adding the public key hash to the server,
// so that other devices can query and request public key.
// Returns assigned Add Code, where 0 < Add Code <= addCodeArrSize
// Returns NoAvailableAddCodeError if all Add Code is in use
func (serv *Server) getAddCode(pubKeyHash string) (addCode int, err error) {
	c, ok := serv.devices.Load(pubKeyHash)
	if !ok || c == nil {
		log.Debug(common.ClientNotFoundError)
		return -1, common.ClientNotFoundError
	}

	cli := c.(*client)

	// serv.nextAddCodeIdxMutex is locked until the return statement of this function
	// since it updates indices. May change depending on the significance of throttling.
	serv.nextAddCodeIdxMutex.Lock()
	defer serv.nextAddCodeIdxMutex.Unlock()

	// Get next available Add Code.
	// Users could forget to switch unregister themselves and still occupy the AddCode,
	// so we need to check if the Add Code is actually available.
	serv.addCodeArrMutex.RLock()
	elem := serv.addCodeArr[serv.nextAddCodeIdx]
	serv.addCodeArrMutex.RUnlock()

	retry := 0
	// Repeat until available code is found.
	// elem[1] is always string; no need to check for error
	for elem[1].(string) != "" {
		serv.nextAddCodeIdx += 1
		// if serv.nextAddCodeIdx reaches the max size, reset to 0
		if serv.nextAddCodeIdx == addCodeArrSize {
			serv.nextAddCodeIdx = 0
		}

		// Get next available Add Code.
		serv.addCodeArrMutex.RLock()
		elem = serv.addCodeArr[serv.nextAddCodeIdx]
		serv.addCodeArrMutex.RUnlock()

		retry += 1
		// If every possible code is taken, return error
		if retry == addCodeArrSize {
			log.Error("Every add code is being used")
			return -1, common.NoAvailableAddCodeError
		}
	}
	// Get Add Code
	// elem[0] is always int; no need to check for error
	addCode = elem[0].(int)

	// Mark current Add Code as being used
	serv.addCodeArrMutex.Lock()
	serv.addCodeArr[serv.nextAddCodeIdx][1] = pubKeyHash
	serv.addCodeArrMutex.Unlock()

	// Increment next available Add Code index
	serv.nextAddCodeIdx += 1

	// if serv.nextAddCodeIdx reaches the max size, reset to 0
	if serv.nextAddCodeIdx == addCodeArrSize {
		serv.nextAddCodeIdx = 0
	}

	cli.addCodeIdx = serv.addCodeIdx[addCode-1]

	// Log
	//log.Debug("addDev//addCodeArr: ", serv.addCodeArr[serv.nextAddCodeIdx-1])
	//log.Debug(serv.devices.Load(pubKeyHash))

	return addCode, nil
}

func (serv *Server) handleInit(conn net.Conn) (pubKeyH string, err error) {
	msg, err := util.ReadMessage(conn)
	if err != nil {
		return "", err
	}
	//pubKeyHashStr := string(pubKeyHash)
	pubKeyHashStr := string(util.BytesToBase64(msg.Data))

	msg, err = util.ReadMessage(conn)
	if err != nil {
		return "", err
	}

	serv.addDevice(pubKeyHashStr, string(msg.Data), conn)
	log.Info(pubKeyHashStr)
	log.Debug("Client " + pubKeyHashStr[:debugClientNameLen] + ": Registered")

	return pubKeyHashStr, nil
}

func (serv *Server) handleQuit(pubKeyHash string) {
	serv.removeDevice(pubKeyHash)
	log.Debug("Client " + pubKeyHash[:debugClientNameLen] + ": Unregistered")
}

func (serv *Server) handleGetAddCode(conn net.Conn, pubKeyHash string) (err error) {
	var command = common.GetAddCode
	addCode, err := serv.getAddCode(pubKeyHash)
	if err != nil {
		return err
	}
	_, err = util.WriteMessage(conn, []byte(fmt.Sprintf("%06d", addCode)), nil, command)
	if err != nil {
		return err
	}

	log.Debugf("Client %s: Allocated Add Code [%06d]", pubKeyHash[:debugClientNameLen], addCode)

	return nil
}

func (serv *Server) handleRemoveAddCode(conn net.Conn, pubKeyHash string) (err error) {
	// Get Add Code
	msg, err := util.ReadMessage(conn)
	if err != nil {
		return err
	}
	addCode, err := strconv.Atoi(string(msg.Data))
	if err != nil {
		return err
	}
	if err = serv.removeAddCode(addCode, pubKeyHash); err != nil {
		return err
	}

	log.Debugf("Client %s: Freed Add Code [%06d]", pubKeyHash[:debugClientNameLen], addCode)

	return nil
}

// TODO: Work in progress
func (serv *Server) handleRequestRelay(conn net.Conn) (err error) {
	msg, err := util.ReadMessage(conn)
	if err != nil {
		return err
	}
	c, ok := serv.devices.Load(string(msg.Data))
	if !ok || c == nil {
		log.Debug(common.ClientNotFoundError)
		return common.ClientNotFoundError
	}

	receiver := c.(*client)

	var endNow string
	for endNow == common.EndRelay.String {
		// TODO: Send command/Result to rx?
		written, err := util.ReadBytesToWriter(conn, receiver.connToClient, true)
		if err != nil {
			log.Debug(err)
			log.Debug("Relayed bytes count: ", written)
			log.Error("Error while relaying data")
			return err
		}
		// TODO: Fix
		//end, err := util.ReadBytes(conn)
		//if err != nil {
		//	log.Debug(err)
		//	return err
		//}
		//endNow = string(end)
	}

	return nil
}

func (serv *Server) handleRequestPubKey(conn net.Conn) (err error) {
	var command = common.GetPubKey
	msg, err := util.ReadMessage(conn)
	if err != nil {
		return err
	}
	rxAddCode, err := strconv.Atoi(string(msg.Data))
	addCodeIdx := serv.addCodeIdx[rxAddCode-1]
	serv.addCodeArrMutex.RLock()
	rxPubKeyH := serv.addCodeArr[addCodeIdx][1].(string)
	serv.addCodeArrMutex.RUnlock()

	c, ok := serv.devices.Load(rxPubKeyH)
	if !ok || c == nil {
		log.Debug(common.ClientNotFoundError)
		return common.ClientNotFoundError
	}
	cli := c.(*client)
	if _, err = util.WriteMessage(cli.connToClient, nil, nil, command); err != nil {
		log.Debug(err)
		log.Error("Error while sending command to rx client")
		return err
	}

	defer func() {
		_ = writeResult(cli.connToClient, err, command)
	}()

	if _, err = util.ReadBytesToWriter(cli.connToClient, conn, true); err != nil {
		log.Debug(err)
		log.Error("Error while relaying public key from rx")

		return err
	}
	return nil
}

func writeResult(conn net.Conn, errorToWrite error, command *common.Command) (err error) {
	var e *common.Error
	if errorToWrite != nil {
		log.Debug(errorToWrite)
		cErr, ok := errorToWrite.(*common.Error)
		if ok {
			e = cErr
		} else {
			e = common.GeneralServerError
		}
	} else {
		e = nil
	}
	if _, err = util.WriteMessage(conn, nil, e, command); err != nil {
		log.Debug(err)
		return err
	}
	return nil
}

func (serv *Server) connectionHandler(conn net.Conn) (err error) {
	// Close connection after using
	defer func() {
		if e := conn.Close(); e != nil {
			log.Debug(e)
			log.Error("Error while closing conn")
			err = e
			return
		}
	}()

	// If initialization fails, attempt to write the error code
	// to the client, then close the connection
	pubKeyHash, err := serv.handleInit(conn)
	if _ = writeResult(conn, err, common.Init); err != nil {
		log.Debug(err)
		log.Error("Error while initializing client")
		return err
	}

	// If initialization succeeds, make sure the client switch to offline properly;
	// If the client was using Add Code, mark it as available and remove the client
	// from "online" list
	//
	// Since defer calls are executed in LIFO order, this defer statement
	// will be called before the defer statement above
	defer func() {
		serv.handleQuit(pubKeyHash)
	}()

	isQuit := false
	for !isQuit {
		m, e := util.ReadMessage(conn)
		if e != nil {
			return e
		}
		command := common.CommandCodes[m.CommandCode]
		log.Debug("Client " + pubKeyHash[:debugClientNameLen] + ": Command//" + command.String)
		switch command {
		case common.GetAddCode:
			err = serv.handleGetAddCode(conn, pubKeyHash)
		case common.RemoveAddCode:
			err = serv.handleRemoveAddCode(conn, pubKeyHash)
		case common.RequestRelay:
			err = serv.handleRequestRelay(conn)
		case common.RequestPubKey:
			err = serv.handleRequestPubKey(conn)
		case common.RequestP2P:
			err = serv.handleInitP2P(conn, pubKeyHash)
		case common.Quit:
			isQuit = true
		default:
			log.Debug(common.UnknownCommandError)
			return common.UnknownCommandError
		}
		if err = writeResult(conn, err, command); err != nil {
			return err
		}
	}

	return err
}

func (serv *Server) Start() (err error) {
	listener, err := tls.Listen("tcp", fmt.Sprint(serv.Host, ":", serv.Port), serv.tls)
	if err != nil {
		log.Debug(err)
		log.Fatal("Listener cannot be initialized")
		os.Exit(1)
	}
	defer func() {
		if e := listener.Close(); e != nil {
			log.Debug(err)
			log.Error("Error while closing listener")
			err = e
		}
	}()
	for {
		// tlsConn is closed in connectionHandler to prevent
		// memory leak caused by using defer in a loop
		tlsConn, err := listener.Accept()
		if err != nil {
			log.Debug(err)
			log.Warning("Error while accepting connection")
			return err
		}
		log.Info("--- New connection established ---")
		log.Info("RemoteAddr: ", tlsConn.RemoteAddr())
		go func() {
			if e := serv.connectionHandler(tlsConn); e != nil {
				log.Debug(e)
				log.Error("Error returned by connectionHandler")
			}
		}()
	}
	return err
}

// handleInitP2P
/*
	Order of operations for initiating client (tx):
	Initiate p2p with common.RequestP2P command
	Send PubKey hash of peer in which to connect to (rx)
	Accept local IP of rx
	Accept remote IP of rx
*/

func (serv *Server) handleInitP2P(txConn net.Conn, txHash string) (err error) {
	log.Info("P2P request from: ", txConn.RemoteAddr())
	a, exists := serv.devices.Load(txHash)
	if !exists {
		return common.ClientNotFoundError
	}
	txClient := a.(*client)
	txMsg, err := util.ReadMessage(txConn)
	if err != nil {
		log.Debug(err)
		log.Error("Error while connecting to the server")
		return err
	}

	// TODO create error for nil hash
	if txMsg.Data == nil {
		return common.GeneralServerError
	}

	// get client structure of peer
	c, ok := serv.devices.Load(string(txMsg.Data))
	if !ok || c == nil {
		_, err = util.WriteMessage(txConn, nil, common.ClientNotFoundError, common.RequestP2P)
		return common.ClientNotFoundError
	}
	rxCli := c.(*client)
	log.Debug("client found: ", rxCli.pubKeyHash, rxCli.localAddr, rxCli.publicAddr)
	// send requestptp command to receiver
	_, err = util.WriteMessage(rxCli.connToClient, nil, nil, common.RequestP2P)

	// send tx pkhash to receiver
	_, err = util.WriteMessage(rxCli.connToClient, []byte(txHash), nil, common.RequestP2P)

	// read for RequestlocalIP from receiver
	rxMsg, _ := util.ReadMessage(rxCli.connToClient)
	log.Debug(string(rxMsg.Data))
	if bytes.Compare(rxMsg.Data, []byte("LCIP")) != 0 {
		return common.TaskNotCompleteError
	}
	// send tx localIP to receiver
	_, err = util.WriteMessage(rxCli.connToClient, []byte(txClient.localAddr), nil, common.RequestP2P)

	// read for RequestpublicIP from receiver
	rxMsg, _ = util.ReadMessage(rxCli.connToClient)
	if bytes.Compare(rxMsg.Data, []byte("PBIP")) != 0 {
		return common.TaskNotCompleteError
	}

	// send tx publicIP to receiver
	_, err = util.WriteMessage(rxCli.connToClient, []byte(txClient.publicAddr), nil, common.RequestP2P)

	// send rx localIP to tx
	_, err = util.WriteMessage(txConn, []byte(rxCli.localAddr), nil, common.RequestP2P)

	// send rx publicIP to tx
	_, err = util.WriteMessage(txConn, []byte(rxCli.publicAddr), nil, common.RequestP2P)
	if err != nil {
		log.Error("Error writing to client")
		return err
	}
	return err
}

//func (serv *Server) handleGetLocalIP(conn net.Conn) (localIP string, err error) {
//	err = writeResult(conn, nil, common.GetLocalIP)
//	if err != nil {
//		return "", err
//	}
//	clientLocalIP, err := util.ReadString(conn)
//	if err != nil {
//		log.Error("Error receiving local IP address")
//		return "", err
//	}
//	log.Debug(clientLocalIP)
//	local, _ := net.ResolveIPAddr("IP", clientLocalIP)
//	return local.String(), err
//}
