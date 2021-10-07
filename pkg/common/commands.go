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
	RequestPTPip  Command = "RPTP" // request peer to peer ip address
)

func (c Command) String() string {
	return string(c)
}
