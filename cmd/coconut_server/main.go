package main

import (
	"github.com/jaeha-choi/Proj_Coconut_Server/internal/server"
)

func main() {
	server.Start("../../config/config.yml")
}
