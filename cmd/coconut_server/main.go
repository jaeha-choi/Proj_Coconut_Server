package main

import (
	"github.com/jaeha-choi/Proj_Coconut_Server/internal/server"
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"github.com/jaeha-choi/Proj_Coconut_Utility/util"
)

func main() {
	confPath := "./config/config.yml"
	var serv *server.Server
	var err error
	if serv, err = server.ReadConfig(confPath); err != nil {
		log.Debug(err)
		log.Warning("Could not read config, trying default config")
		if serv, err = server.InitConfig(); err != nil {
			log.Debug(err)
			log.Fatal("Could not load default config")
			return
		}
	}

	if err := serv.Start(); err != nil {
		log.Debug(err)
		log.Error("Error caused by server.Start()")
	}

	if err := util.WriteConfig(confPath, serv); err != nil {
		log.Debug(err)
		log.Warning("Could not save config")
	}
}
