package main

import (
	"os"

	"github.com/travisperson/secure-wallet/build"
	"github.com/travisperson/secure-wallet/cmd/secure-wallet/cmds"
	"github.com/travisperson/secure-wallet/internal/logging"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:     "secure-wallet",
		Usage:    "secure wallet software suite",
		Version:  build.Version(),
		Flags:    []cli.Flag{},
		Commands: cmds.Commands,
	}

	err := app.Run(os.Args)
	if err != nil {
		logging.Logger.Errorw("exit", "error", err)
		os.Exit(1)
	}
}
