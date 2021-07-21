package server

import (
	"github.com/jaeha-choi/Proj_Coconut_Utility/log"
	"github.com/jaeha-choi/Proj_Coconut_Utility/util"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func init() {
	log.Init(os.Stdout, log.DEBUG)
}

func TestInitConfig(t *testing.T) {
	t.Cleanup(cleanUpHelper)
	createCopy("../../data/cert/server.crt", "./data/cert/server.crt")
	createCopy("../../data/cert/server.key", "./data/cert/server.key")

	if err := os.MkdirAll("./config", os.ModePerm); err != nil {
		log.Debug(err)
		log.Error("Error while creating tmp directory")
		return
	}

	confPath := "./config/config.yml"
	serv, err := InitConfig()
	if err != nil {
		log.Debug(err)
		t.Fatal("Could not load default config")
		return
	}
	if err := util.WriteConfig(confPath, serv); err != nil {
		log.Debug(err)
		t.Fatal("Could not save config")
	}
	testConf, err := ReadConfig("../../config/config.yml")
	if err != nil || testConf == nil {
		t.Error("readConfig error")
	}
	if testConf.Host != "127.0.0.1" {
		t.Error("readConfig host incorrect")
	}
	if testConf.Port != 9129 {
		t.Error("readConfig port incorrect")
	}
}

func TestAddRemoveDev(t *testing.T) {
	t.Cleanup(cleanUpHelper)
	createCopy("../../data/cert/server.crt", "./data/cert/server.crt")
	createCopy("../../data/cert/server.key", "./data/cert/server.key")

	if err := os.MkdirAll("./config", os.ModePerm); err != nil {
		log.Debug(err)
		log.Error("Error while creating tmp directory")
		return
	}
	confPath := "../../config/config.yml"
	var serv *Server
	var err error
	if serv, err = ReadConfig(confPath); err != nil {
		log.Debug(err)
		log.Warning("Could not read config, trying default config")
		if serv, err = InitConfig(); err != nil {
			log.Debug(err)
			t.Error("Could not load default config")
			return
		}
	}

	code, err := serv.AddDevice("abcd")
	if err != nil {
		log.Debug(err)
		t.Error("Error in AddDevice")
		return
	}
	code2, err := serv.AddDevice("efgh")
	if err != nil {
		log.Debug(err)
		t.Error("Error in AddDevice")
		return
	}
	serv.RemoveDevice(code)
	serv.RemoveDevice(code2)
}

// Comment out until the function is implemented
//func TestStartListener(t *testing.T) {
//	testConf, err := ReadConfig("../../config/config.yml")
//	if err != nil {
//		t.Error("readConfig returned error")
//	}
//	go func() {
//		if err := testConf.Start(); err != nil {
//			t.Error("Error while starting listener")
//		}
//	}()
//	_, err = net.Dial("tcp", "localhost:9129")
//	if err != nil {
//		t.Error("Error while connecting to server")
//	}
//}

func createCopy(src string, dst string) {
	srcFile, err := ioutil.ReadFile(src)
	if err != nil {
		log.Debug(err)
		log.Error("Could not open src file to copy")
		return
	}
	dir, _ := filepath.Split(dst)
	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		log.Debug(err)
		log.Error("Error while creating tmp directory")
		return
	}
	if err := ioutil.WriteFile(dst, srcFile, 0777); err != nil {
		log.Debug(err)
		log.Error("Error while writing file")
		return
	}
}

func cleanUpHelper() {
	if err := os.RemoveAll("./data"); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
	if err := os.RemoveAll("./config"); err != nil {
		log.Debug(err)
		log.Error("Existing directory not deleted, perhaps it does not exist?")
	}
}
