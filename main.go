package main

import (
	"github.com/bohdanstryber/auth-go/app"
	"github.com/bohdanstryber/banking-go/logger"
)

func main() {
	logger.Info("Starting auth app...")
	app.Start()
}
