package src

import (
	"testing"
)

func TestReadConfigConf(t *testing.T) {
	testConf, _ := readConfig("../config.yml")
	if testConf == nil {
		t.Error("readConfig returned nil")
	}
}

func TestReadConfigError(t *testing.T) {
	_, err := readConfig("../config.yml")
	if err != nil {
		t.Error("readConfig returned error")
	}
}

func TestReadConfigHost(t *testing.T) {
	testConf, _ := readConfig("../config.yml")
	if testConf.Server.Host != "127.0.0.1" {
		t.Error("readConfig host incorrect")
	}
}

func TestReadConfigPort(t *testing.T) {
	testConf, _ := readConfig("../config.yml")
	if testConf.Server.Port != 9129 {
		t.Error("readConfig port incorrect")
	}
}
