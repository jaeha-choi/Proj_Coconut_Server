package server

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
)

// Server related configurations
type Server struct {
	Host     string `yaml:"host"`
	Port     uint16 `yaml:"port"`
	CertPath string `yaml:"cert_path"`
	tls      *tls.Config
}

const (
	keyPairName = "server"
)

func init() {
	log.Init(os.Stdout, log.DEBUG)
}

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

func InitConfig() (serv *Server, err error) {
	serv = &Server{
		Host:     "127.0.0.1",
		Port:     9129,
		CertPath: "./data/cert",
	}
	if err := serv.tlsConfig(); err != nil {
		return nil, err
	}
	return serv, nil
}

// ReadConfig reads a config from a yaml file
func ReadConfig(fileName string) (serv *Server, err error) {
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
	if err := serv.tlsConfig(); err != nil {
		return nil, err
	}
	return serv, nil
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
