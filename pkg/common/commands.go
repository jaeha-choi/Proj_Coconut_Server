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
	GetPTPip      Command = "GPTP" // get peer to peer ip address
	RequestPTPip  Command = "RPTP" // request peer to peer ip address
	//GetPTPInit    Command = "PTPI" // get peer to peer init packet (does not have request
	// because packets will be thrown away)
)

func (c Command) String() string {
	return string(c)
}
