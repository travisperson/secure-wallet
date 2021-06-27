package cmds

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/filecoin-project/go-address"
	lapi "github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/travisperson/secure-wallet/internal/logging"
	"github.com/urfave/cli/v2"
)

var clientCommands = []*cli.Command{
	{
		Name:      "has",
		Usage:     "WalletHas",
		ArgsUsage: "<address...>",
		Action: func(cctx *cli.Context) error {
			ctx := context.Background()

			wapi, closer, err := getCliClient(ctx, cctx)
			defer closer()
			if err != nil {
				return err
			}

			for _, wallet := range cctx.Args().Slice() {
				addr, err := address.NewFromString(cctx.Args().First())
				if err != nil {
					logging.Logger.Errorf("failed to parse wallet", "wallet", wallet, "err", err)
				}

				if has, err := wapi.WalletHas(ctx, addr); err != nil {
					logging.Logger.Errorf("request failed", "wallet", addr.String(), "err", err)
				} else {
					fmt.Printf("%s %t\n", addr, has)
				}
			}

			return nil
		},
	},
	{
		Name:  "list",
		Usage: "WalletList",
		Action: func(cctx *cli.Context) error {
			ctx := context.Background()

			wapi, closer, err := getCliClient(ctx, cctx)
			defer closer()
			if err != nil {
				return err
			}

			addrs, err := wapi.WalletList(ctx)
			if err != nil {
				logging.Logger.Errorf("request failed", "err", err)
			}

			for _, addr := range addrs {
				fmt.Printf("%s\n", addr)
			}

			return nil
		},
	},
	{
		Name:      "sign",
		Usage:     "WalletSign",
		ArgsUsage: "<signing address> <hexMessage>",
		Action: func(cctx *cli.Context) error {
			ctx := context.Background()

			wapi, closer, err := getCliClient(ctx, cctx)
			defer closer()
			if err != nil {
				return err
			}

			if !cctx.Args().Present() || cctx.NArg() != 2 {
				return fmt.Errorf("must specify signing address and message to sign")
			}

			addr, err := address.NewFromString(cctx.Args().First())
			if err != nil {
				return err
			}

			msg, err := hex.DecodeString(cctx.Args().Get(1))
			if err != nil {
				return err
			}

			sig, err := wapi.WalletSign(ctx, addr, msg, lapi.MsgMeta{})
			if err != nil {
				return err
			}

			sigBytes := append([]byte{byte(sig.Type)}, sig.Data...)

			fmt.Println(hex.EncodeToString(sigBytes))

			return nil
		},
	},
	{
		Name:      "new",
		Usage:     "WalletNew",
		ArgsUsage: "<bls|secp256k1>",
		Action: func(cctx *cli.Context) error {
			ctx := context.Background()

			wapi, closer, err := getCliClient(ctx, cctx)
			defer closer()
			if err != nil {
				return err
			}

			if !cctx.Args().Present() {
				return fmt.Errorf("key type is required")
			}

			keyType := types.KeyType(cctx.Args().First())

			addr, err := wapi.WalletNew(ctx, keyType)
			if err != nil {
				return err
			}

			fmt.Printf("%s\n", addr)

			return nil
		},
	},
	{
		Name:      "import",
		Usage:     "WalletImport",
		ArgsUsage: "[path]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "format",
				Usage: "specify input format for key <hex-lotus|json-lotus>",
				Value: "hex-lotus",
			},
		},
		Action: func(cctx *cli.Context) error {
			ctx := context.Background()

			wapi, closer, err := getCliClient(ctx, cctx)
			defer closer()
			if err != nil {
				return err
			}

			var input io.Reader
			if !cctx.Args().Present() {
				input = os.Stdin
			} else {
				var err error
				inputFile, err := os.Open(cctx.Args().First())
				if err != nil {
					return err
				}
				defer inputFile.Close()
				input = bufio.NewReader(inputFile)
			}

			data, err := ioutil.ReadAll(input)
			if err != nil {
				return err
			}

			var ki types.KeyInfo
			switch cctx.String("format") {
			case "hex-lotus":
				data, err := hex.DecodeString(strings.TrimSpace(string(data)))
				if err != nil {
					return err
				}

				if err := json.Unmarshal(data, &ki); err != nil {
					return err
				}
			case "json-lotus":
				if err := json.Unmarshal(data, &ki); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unrecognized format: %s", cctx.String("format"))
			}

			addr, err := wapi.WalletImport(ctx, &ki)
			if err != nil {
				return err
			}

			fmt.Printf("%s\n", addr)

			return nil
		},
	},
	{
		Name:      "export",
		Usage:     "WalletExport",
		ArgsUsage: "<address>",
		Action: func(cctx *cli.Context) error {
			ctx := context.Background()

			wapi, closer, err := getCliClient(ctx, cctx)
			defer closer()
			if err != nil {
				return err
			}

			if !cctx.Args().Present() {
				return fmt.Errorf("must specify wallet to export")
			}

			addr, err := address.NewFromString(cctx.Args().First())
			if err != nil {
				return err
			}

			ki, err := wapi.WalletExport(ctx, addr)
			if err != nil {
				return err
			}

			b, err := json.Marshal(ki)
			if err != nil {
				return err
			}

			fmt.Println(hex.EncodeToString(b))

			return nil
		},
	},
	{
		Name:      "delete",
		Usage:     "WalletDelete",
		ArgsUsage: "<address...>",
		Action: func(cctx *cli.Context) error {
			ctx := context.Background()

			wapi, closer, err := getCliClient(ctx, cctx)
			defer closer()
			if err != nil {
				return err
			}

			for _, wallet := range cctx.Args().Slice() {
				addr, err := address.NewFromString(cctx.Args().First())
				if err != nil {
					logging.Logger.Errorf("failed to parse wallet", "wallet", wallet, "err", err)
				}

				if err := wapi.WalletDelete(ctx, addr); err != nil {
					logging.Logger.Errorf("request failed", "wallet", addr.String(), "err", err)
				} else {
					fmt.Printf("%s deleted\n", addr)
				}

			}

			return nil
		},
	},
}
