package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "AuditLab",
		Usage: "tool for auditing",
		Commands: []*cli.Command{
			{
				Name:  "whoami",
				Usage: "github user identification",
				Action: func(cCtx *cli.Context) error {
					fmt.Println("authenticated")
					return nil
				},
			},
			{
				Name:  "login",
				Usage: "github login",
				Action: func(cCtx *cli.Context) error {
					fmt.Println("logging in ", cCtx.Args().First())
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
