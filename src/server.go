package src

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
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

// readConfig reads a config from a yaml file
func readConfig(fileName string) (*Config, error) {
	var configVar Config
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Println("Error while reading config.yml")
		return nil, err
	}
	err = yaml.Unmarshal(file, &configVar)
	if err != nil {
		log.Println("Error while parsing config.yml")
		return nil, err
	}
	return &configVar, nil
}

func Start() {
	conf, err := readConfig("config.yml")
	if err == nil {
		log.Println(conf.Server.Port)
	}
}