package main

import (
	"flag"
	"github.com/jaeha-choi/Proj_Coconut_Server/internal/server"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"github.com/jaeha-choi/Proj_Coconut_Utility/util"
	"os"
)

func main() {
	// Command line arguments (flags) overrides configuration file, if exist

	// Double dash arguments (e.g. --config-path) is not possible with "flag" package it seems like. Consider
	// Using "getopt" package.
	confPath := flag.String("config-path", "./config/config.yml", "Configuration file path")
	logLevelArg := flag.String("log-level", "warning", "Logging level")

	serverHostFlag := flag.String("host", "", "Server address")
	serverPortFlag := flag.Int("port", 0, "Server port")
	serverCertPathFlag := flag.String("cert-path", "", "Server certification file path")

	flag.Parse()

	// Setup logger
	var logLevel log.LoggingMode
	switch *logLevelArg {
	case "debug":
		logLevel = log.DEBUG
	case "info":
		logLevel = log.INFO
	case "warning":
		logLevel = log.WARNING
	case "error":
		logLevel = log.ERROR
	case "fatal":
		logLevel = log.FATAL
	default:
		logLevel = log.WARNING
	}
	log.Init(os.Stdout, logLevel)

	var serv *server.Server
	var err error

	// Read configurations
	if serv, err = server.ReadConfig(*confPath); err != nil {
		log.Debug(err)
		log.Warning("Could not read config, trying default config")
		if serv, err = server.InitConfig(); err != nil {
			log.Debug(err)
			log.Fatal("Could not load default config")
			os.Exit(1)
		}
		if err := util.WriteConfig(*confPath, serv); err != nil {
			log.Debug(err)
			log.Warning("Could not save config")
		}
	}

	// Override configurations if arguments are provided
	if *serverHostFlag != "" {
		serv.Host = *serverHostFlag
	}
	if *serverCertPathFlag != "" {
		serv.CertPath = *serverCertPathFlag
	}
	if 0 < *serverPortFlag && *serverPortFlag < 65536 {
		serv.Port = uint16(*serverPortFlag)
	} else if *serverPortFlag != 0 {
		log.Fatal("Port out of range")
		os.Exit(1)
	}

	// Start the server
	if err := serv.Start(); err != nil {
		log.Debug(err)
		log.Fatal("Error caused by server.Start()")
		os.Exit(1)
	}
}
