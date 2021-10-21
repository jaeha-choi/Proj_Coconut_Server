package common

type Command string

// Commands and responses. Perhaps using string isn't necessary.
const (
	// Commands

	Quit          Command = "QUIT"
	RequestRelay  Command = "RELY"
	EndRelay      Command = "ERLY"
	GetAddCode    Command = "GADC"
	RemoveAddCode Command = "RADC"
	GetPubKey     Command = "GPUB"
	RequestPubKey Command = "RPUB"
	GetPTPKey     Command = "GKEY" // get public key for client you want to connect
	RequestPTP    Command = "RPTP" // request peer to peer ip address
	GetLocalIP    Command = "LCIP" // handle receiving of local ip for p2p connection
	GetPublicIP   Command = "PBIP" // handle receiving public ip address
	HolePunchPING Command = "PING" // init command for p2p connection
	HolePunchPONG Command = "PONG" // init reply to "PING" command
)

func (c Command) String() string {
	return string(c)
}
