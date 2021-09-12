package log

import (
	"fmt"
	"io"
	"log"
)

var logger *log.Logger
var mode LoggingMode

type LoggingMode int

const (
	DEBUG LoggingMode = iota
	INFO
	WARNING
	ERROR
	FATAL
)

// Init initializes the logger
func Init(outTo io.Writer, logMode LoggingMode) {
	mode = logMode
	logger = log.New(outTo, "", log.LstdFlags|log.Lshortfile)
}

// initTesting is similar to Init but without timestamp to make the testing easier
func initTesting(outTo io.Writer, logMode LoggingMode) {
	mode = logMode
	logger = log.New(outTo, "Test: ", 0)
}

// Debug logs only if LoggingMode is set to DEBUG
func Debug(msg ...interface{}) {
	if mode <= DEBUG {
		_ = logger.Output(2, "DEBUG:\t"+fmt.Sprint(msg...))
	}
}

// Debugf logs if LoggingMode is set to DEBUG or lower
func Debugf(format string, msg ...interface{}) {
	if mode <= DEBUG {
		_ = logger.Output(2, "DEBUG:\t"+fmt.Sprintf(format, msg...))
	}
}

// Info logs if LoggingMode is set to INFO or lower
func Info(msg ...interface{}) {
	if mode <= INFO {
		_ = logger.Output(2, "INFO:\t"+fmt.Sprint(msg...))
	}
}

// Infof logs if LoggingMode is set to INFO or lower
func Infof(format string, msg ...interface{}) {
	if mode <= INFO {
		_ = logger.Output(2, "INFO:\t"+fmt.Sprintf(format, msg...))
	}
}

// Warning logs if LoggingMode is set to WARNING or lower
func Warning(msg ...interface{}) {
	if mode <= WARNING {
		_ = logger.Output(2, "WARNING:\t"+fmt.Sprint(msg...))
	}
}

// Warningf logs if LoggingMode is set to WARNING or lower
func Warningf(format string, msg ...interface{}) {
	if mode <= WARNING {
		_ = logger.Output(2, "WARNING:\t"+fmt.Sprintf(format, msg...))
	}
}

// Error logs if LoggingMode is set to ERROR or lower
func Error(msg ...interface{}) {
	if mode <= ERROR {
		_ = logger.Output(2, "ERROR:\t"+fmt.Sprint(msg...))
	}
}

// Errorf logs if LoggingMode is set to ERROR or lower
func Errorf(format string, msg ...interface{}) {
	if mode <= ERROR {
		_ = logger.Output(2, "Error:\t"+fmt.Sprintf(format, msg...))
	}
}

// Fatal always logs when used
func Fatal(msg ...interface{}) {
	_ = logger.Output(2, "FATAL:\t"+fmt.Sprint(msg...))
}

// Fatalf always logs when used
func Fatalf(format string, msg ...interface{}) {
	_ = logger.Output(2, "FATAL:\t"+fmt.Sprintf(format, msg...))
}
