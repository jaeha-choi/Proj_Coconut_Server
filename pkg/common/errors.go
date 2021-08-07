package common

import (
	"errors"
	"strconv"
)

type Error struct {
	Err     error
	ErrCode uint8
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return "error code " + strconv.FormatUint(uint64(e.ErrCode), 10) + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error         { return e.Err }
func (e *Error) GetCode() (code uint8) { return e.ErrCode }

var ErrorCodes = [255]*Error{
	nil, // Error code 0 means no error
	UnknownCodeError,
	UnexpectedCommandError,
	ExistingConnError,
	ReceiverNotFound,
	TaskNotCompleteError,
}

var UnknownCodeError = &Error{
	Err:     errors.New("unknown error code returned"),
	ErrCode: 1,
}

var UnexpectedCommandError = &Error{
	Err:     errors.New("unexpected command returned"),
	ErrCode: 2,
}

var ExistingConnError = &Error{
	Err:     errors.New("existing connection present in client struct"),
	ErrCode: 3,
}

var ReceiverNotFound = &Error{
	Err:     errors.New("receiver was not found"),
	ErrCode: 4,
}

var TaskNotCompleteError = &Error{
	Err:     errors.New("task not complete"),
	ErrCode: 5,
}
