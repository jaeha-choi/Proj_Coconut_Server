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

var ErrorCodes = [256]*Error{
	nil, // Error code 0 means no error
	UnknownCodeError,
	UnknownCommandError,
	GeneralServerError,
	GeneralClientError,
	TaskNotCompleteError,
	PubKeyMismatchError,
	ClientNotFoundError,
	ReceiverNotFound,
	ReceiverNotAvailable,
	NoAvailableAddCodeError,
	ExistingConnError,
	PeerUnavailableError,
	PubKeyNotFoundError,
	ClosedConnError,
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

var GeneralClientError = &Error{
	Err:     errors.New("general server error"),
	ErrCode: 4,
}

var TaskNotCompleteError = &Error{
	Err:     errors.New("task not complete"),
	ErrCode: 5,
}

var PubKeyMismatchError = &Error{
	Err:     errors.New("public key mismatch"),
	ErrCode: 6,
}

var ClientNotFoundError = &Error{
	Err:     errors.New("client not found error"),
	ErrCode: 7,
}

var ReceiverNotFound = &Error{
	Err:     errors.New("receiver was not found"),
	ErrCode: 8,
}

var ReceiverNotAvailable = &Error{
	Err:     errors.New("receiver is not available"),
	ErrCode: 9,
}

var NoAvailableAddCodeError = &Error{
	Err:     errors.New("no available add code error"),
	ErrCode: 10,
}

var ExistingConnError = &Error{
	Err:     errors.New("existing connection present in client struct"),
	ErrCode: 11,
}

var PeerUnavailableError = &Error{
	Err:     errors.New("unable to establish connection with peer"),
	ErrCode: 12,
}

var PubKeyNotFoundError = &Error{
	Err:     errors.New("public key of peer not found"),
	ErrCode: 13,
}

var ClosedConnError = &Error{
	Err:     errors.New("connection was closed by peer"),
	ErrCode: 14,
}
