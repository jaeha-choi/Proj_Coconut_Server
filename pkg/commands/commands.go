package commands

//type Command string

// Commands and responses. Perhaps using string isn't necessary.
const (
	// Commands

	Quit          = "QUIT"
	RequestRelay  = "RELY"
	EndRelay      = "ERLY"
	GetAddCode    = "GADC"
	RemoveAddCode = "RADC"
	GetPubKey     = "GPUB"
	ReqPubKey     = "RPUB"

	// Response

	Affirmation = "A"
	Negation    = "N"
)
