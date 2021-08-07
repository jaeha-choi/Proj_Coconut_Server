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
	UnknownCommandError,
	GeneralServerError,
	TaskNotCompleteError,
	PubKeyMismatchError,
	ClientNotFoundError,
	ReceiverNotFound,
	ReceiverNotAvailable,
	NoAvailableAddCodeError,
	ExistingConnError,
}

var UnknownCodeError = &Error{
	Err:     errors.New("unknown error code returned"),
	ErrCode: 1,
}

var UnknownCommandError = &Error{
	Err:     errors.New("unknown command returned"),
	ErrCode: 2,
}

var GeneralServerError = &Error{
	Err:     errors.New("general server error"),
	ErrCode: 3,
}

var TaskNotCompleteError = &Error{
	Err:     errors.New("task not complete"),
	ErrCode: 4,
}

var PubKeyMismatchError = &Error{
	Err:     errors.New("public key mismatch"),
	ErrCode: 5,
}

var ClientNotFoundError = &Error{
	Err:     errors.New("client not found error"),
	ErrCode: 6,
}

var ReceiverNotFound = &Error{
	Err:     errors.New("receiver was not found"),
	ErrCode: 7,
}

var ReceiverNotAvailable = &Error{
	Err:     errors.New("receiver is not available"),
	ErrCode: 8,
}

var NoAvailableAddCodeError = &Error{
	Err:     errors.New("no available add code error"),
	ErrCode: 9,
}

var ExistingConnError = &Error{
	Err:     errors.New("existing connection present in client struct"),
	ErrCode: 10,
}
