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
)

func (c Command) String() string {
	return string(c)
}
