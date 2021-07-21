package server

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	mRand "math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
)

const (
	// Name for the public/private key pair
	keyPairName = "server"
	// addCodeArrSize is the max number for Add Code
	addCodeArrSize = 999999
)

// Server related configurations
type Server struct {
	Host     string `yaml:"host"`
	Port     uint16 `yaml:"port"`
	CertPath string `yaml:"cert_path"`

	addCodeArrMutex *sync.RWMutex
	// addCodeArr stores shuffled Add Code in integer with a boolean indicating
	// the status of the Add Code.
	// True if available for the server to allocate the Add Code to other device, false otherwise.
	// 000 000 is reserved for initial value, and should not be used for allocation.
	// i.e. addCodeArr[index] = [Add Code (int), isUsed (bool)]
	addCodeArr [addCodeArrSize][2]interface{}

	// addCodeIdx stores indices to actual Add Code (inverse of addCodeArr)
	// i.e. addCodeIdx[addCode] = index to Add Code in addCodeArr
	// Requires no lock as addCodeIdx is read-only after initAddCode()
	addCodeIdx [addCodeArrSize]int

	nextAddCodeIdxMutex *sync.Mutex
	// nextAddCodeIdx represents index of next available Add Code element in addCodeArr
	nextAddCodeIdx int

	// devices store Add Codes as a key (int) and hash of a public key as a value (string).
	devices sync.Map

	tls *tls.Config
}

var NoAvailableAddCodeError = errors.New("no available add code error")

// init initializes logger and set mRand seed
func init() {
	log.Init(os.Stdout, log.DEBUG)
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
		serv.addCodeArr[i] = [2]interface{}{i + 1, false}
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
		//InsecureSkipVerify: false,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		//KeyLogWriter:                nil,
	}

	pair, err := tls.LoadX509KeyPair(filepath.Join(serv.CertPath, keyPairName+".crt"), filepath.Join(serv.CertPath, keyPairName+".key"))
	if err != nil {
		log.Debug(err)
		log.Error("Error while loading .crt and .key file")
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

// RemoveDevice removes a device with provided Add Code from the server,
// preventing other devices from searching this device
func (serv *Server) RemoveDevice(addCode int) {
	// Find the index of Add Code with the inverse array
	addCodeIdx := serv.addCodeIdx[addCode-1]

	// Write lock
	serv.addCodeArrMutex.Lock()
	// Mark the Add Code as available, by setting isUsed field to false
	serv.addCodeArr[addCodeIdx][1] = false
	serv.addCodeArrMutex.Unlock()

	// Remove device from map
	serv.devices.Delete(addCode)

	// Log
	//log.Debug("removeDev//addCodeArr: ", serv.addCodeArr[addCodeIdx])
	//log.Debug(serv.devices.Load(addCode))
}

// AddDevice adds a device by adding the public key hash to the server,
// so that other devices can query and request public key.
// Returns assigned Add Code, where 0 < Add Code <= addCodeArrSize
// Returns NoAvailableAddCodeError if all Add Code is in use
func (serv *Server) AddDevice(pubKeyHash string) (addCode int, err error) {
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
	// elem[1] is always boolean; no need to check for error
	for elem[1].(bool) {
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
			return -1, NoAvailableAddCodeError
		}
	}
	// Get Add Code
	// elem[0] is always int; no need to check for error
	addCode = elem[0].(int)

	// Mark current Add Code as being used
	serv.addCodeArrMutex.Lock()
	serv.addCodeArr[serv.nextAddCodeIdx][1] = true
	serv.addCodeArrMutex.Unlock()

	// Increment next available Add Code index
	serv.nextAddCodeIdx += 1

	// if serv.nextAddCodeIdx reaches the max size, reset to 0
	if serv.nextAddCodeIdx == addCodeArrSize {
		serv.nextAddCodeIdx = 0
	}

	// Add device public key hash to online devices
	serv.devices.Store(addCode, pubKeyHash)

	// Log
	//log.Debug("addDev//addCodeArr: ", serv.addCodeArr[serv.nextAddCodeIdx-1])
	//log.Debug(serv.devices.Load(addCode))
	return addCode, nil
}

func connectionHandler(conn net.Conn) (err error) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debug(err)
			log.Error("Error while closing conn")
			return
		}
	}()
	// TODO: Remove these lines after testing
	b := make([]byte, 5)
	_, _ = conn.Read(b)
	log.Info("Received: ", string(b))

	// Do something here

	return nil
}

func (serv *Server) Start() (err error) {
	listener, err := tls.Listen("tcp", fmt.Sprint(serv.Host, ":", serv.Port), serv.tls)
	if err != nil {
		log.Debug(err)
		log.Fatal("Listener cannot be initialized")
		os.Exit(1)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Debug(err)
			log.Error("Error while closing listener")
		}
	}()
	for {
		// tlsConn is closed in connectionHandler to prevent memory leak
		tlsConn, err := listener.Accept()
		if err != nil {
			log.Debug(err)
			log.Warning("Error while accepting connection")
			return err
		}
		log.Debug("RemoteAddr: ", tlsConn.RemoteAddr())
		log.Debug("LocalAddr: ", tlsConn.LocalAddr())
		log.Info("Connection established")
		if err := connectionHandler(tlsConn); err != nil {
			return err
		}
		break // TODO: Remove this line
	}
	return nil
}
