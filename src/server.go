package src

import (
	"../log"
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"net"
	"os"
)

// Config stores all configurations (server, db, etc)
type Config struct {
	Server Server `yaml:"server"`
}

// Server related configurations
type Server struct {
	Host string `yaml:"host"`
	Port uint16 `yaml:"port"`
}

// Client contains information about each client devices
type Client struct {
	PublicIp    string `json:"publicIp"`
	PrivateIp   string `json:"privateIp"`
	PublicPort  string `json:"publicPort"`
	PrivatePort string `json:"privatePort"`
}

// readConfig reads a config from a yaml file
func readConfig(fileName string) (*Config, error) {
	var configVar Config
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Error("Error while reading config.yml")
		return nil, err
	}
	err = yaml.Unmarshal(file, &configVar)
	if err != nil {
		log.Error("Error while parsing config.yml")
		return nil, err
	}
	return &configVar, nil
}

func startListener(conf *Config) error {
	listener, err := net.Listen("tcp", fmt.Sprint(conf.Server.Host, ":", conf.Server.Port))
	if err != nil {
		log.Fatal("Listener cannot be initialized")
		os.Exit(1)
	}
	defer func() {
		err = listener.Close()
		log.Error("Error while closing listener")
	}()
	// Add loop here
	_, err = listener.Accept()
	if err != nil {
		log.Warning("Error while accepting connection")
		return err
	}
	fmt.Println("Connection established")
	return nil
}

func Start(configName string) {
	log.Init(os.Stdout, log.DEBUG)
	conf, err := readConfig(configName)
	if conf == nil || err != nil {
		log.Fatal("Error while reading config")
		os.Exit(1)
	}
	err = startListener(conf)
}
