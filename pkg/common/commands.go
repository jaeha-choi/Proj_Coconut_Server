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
	GetP2PKey,
	RequestPTP,
	HolePunchPING,
	HolePunchPONG,
}

var Init = &Command{
	String: "Init",
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

// GetP2PKey get public key for client you want to connect
var GetP2PKey = &Command{
	String: "GKEY",
	Code:   8,
}

// RequestPTP request peer to peer ip address
var RequestPTP = &Command{
	String: "RPTP",
	Code:   9,
}

// HolePunchPING init command for p2p connection
var HolePunchPING = &Command{
	String: "PING",
	Code:   10,
}

// HolePunchPONG init reply to "PING" command
var HolePunchPONG = &Command{
	String: "PONG",
	Code:   11,
}
