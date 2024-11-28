package main

import (
	"flag"
	"log"
	"log/slog"
	"os"

	"github.com/ayn2op/discordo/cmd"
	"github.com/ayn2op/discordo/internal/config"
	"github.com/zalando/go-keyring"
)

func main() {
	f, err := os.OpenFile("logfile", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	token := flag.String("token", "", "authentication token")
	flag.Parse()

	// If no token was provided, look it up in the keyring
	if *token == "" {
		t, err := keyring.Get(config.Name, "token")
		if err != nil {
			slog.Info("failed to get token from keyring", "err", err)
		} else {
			*token = t
		}
	}

	if err := cmd.Run(*token); err != nil {
		slog.Error("failed to run", "err", err)
	}
}
