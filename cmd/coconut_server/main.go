package main

import (
	"../../internal/server"
)

func main() {
	server.Start("../../config/config.yml")
}
