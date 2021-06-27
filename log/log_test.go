package log

import (
	"bytes"
	"os"
	"testing"
)

func TestInit(t *testing.T) {
	initTesting(os.Stdout, DEBUG)
}

func TestDebug(t *testing.T) {
	var buffer bytes.Buffer
	initTesting(&buffer, DEBUG)
	Debug("test debug")
	if "Test: DEBUG:\ttest debug\n" != buffer.String() {
		t.Error("Output mismatch")
	}
	buffer.Reset()
	Info("test info")
	if "Test: INFO:\ttest info\n" != buffer.String() {
		t.Error("Output mismatch")
	}
}

func TestInfo(t *testing.T) {
	var buffer bytes.Buffer
	initTesting(&buffer, INFO)
	Debug("test debug")
	// Should not print anything as INFO is higher level
	if "" != buffer.String() {
		t.Error("Output mismatch")
	}
	buffer.Reset()
	Info("test info")
	if "Test: INFO:\ttest info\n" != buffer.String() {
		t.Error("Output mismatch")
	}
}

func TestWarning(t *testing.T) {
	var buffer bytes.Buffer
	initTesting(&buffer, WARNING)
	Info("test info")
	// Should not print anything as WARNING is higher level
	if "" != buffer.String() {
		t.Error("Output mismatch")
	}
	buffer.Reset()
	Warning("test warning")
	if "Test: WARNING:\ttest warning\n" != buffer.String() {
		t.Error("Output mismatch")
	}
}

func TestError(t *testing.T) {
	var buffer bytes.Buffer
	initTesting(&buffer, ERROR)
	Warning("test warning")
	// Should not print anything as ERROR is higher level
	if "" != buffer.String() {
		t.Error("Output mismatch")
	}
	buffer.Reset()
	Error("test error")
	if "Test: ERROR:\ttest error\n" != buffer.String() {
		t.Error("Output mismatch")
	}
}
