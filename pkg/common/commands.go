package common

type Command struct {
	String string
	Code   uint8
}

var CommandCodes = [256]*Command{
	Init,
	Quit,
	RequestPubKey,
	GetPubKey,
	RemoveAddCode,
	GetAddCode,
	EndRelay,
	RequestRelay,
	HandleRequestP2P,
	RequestP2P,
	File,
	Pause,
}

var Init = &Command{
	String: "INIT",
	Code:   0,
}

var Quit = &Command{
	String: "QUIT",
	Code:   1,
}
var RequestPubKey = &Command{
	String: "RPUB",
	Code:   2,
}
var GetPubKey = &Command{
	String: "GPUB",
	Code:   3,
}
var RemoveAddCode = &Command{
	String: "RADC",
	Code:   4,
}
var GetAddCode = &Command{
	String: "GADC",
	Code:   5,
}
var EndRelay = &Command{
	String: "ERLY",
	Code:   6,
}
var RequestRelay = &Command{
	String: "RELY",
	Code:   7,
}
var HandleRequestP2P = &Command{
	String: "HPTP",
	Code:   8,
}

// RequestP2P request peer to peer ip address
var RequestP2P = &Command{
	String: "RPTP",
	Code:   9,
}

// File command is used when exchanging encrypted files
var File = &Command{
	String: "FILE",
	Code:   11,
}

var Pause = &Command{
	String: "PAUS",
	Code:   12,
}
