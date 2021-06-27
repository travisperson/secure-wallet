package cmds

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-jsonrpc"
	"github.com/filecoin-project/go-jsonrpc/auth"
	lapi "github.com/filecoin-project/lotus/api"
	lclient "github.com/filecoin-project/lotus/api/client"
	cliutil "github.com/filecoin-project/lotus/cli/util"
	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gorilla/mux"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/travisperson/secure-wallet/api"
	"github.com/travisperson/secure-wallet/build"
	"github.com/travisperson/secure-wallet/internal/access"
	"github.com/travisperson/secure-wallet/internal/logging"
	"github.com/travisperson/secure-wallet/internal/wallet"
	"github.com/travisperson/secure-wallet/jwtutil"
)

type backendService struct {
	ctx            context.Context
	serviceRouter  *mux.Router
	operatorRouter *mux.Router
	rpc            *jsonrpc.RPCServer
	wallet         lapi.Wallet
	walletCloser   jsonrpc.ClientCloser

	ready   bool
	readyMu sync.Mutex
}

func (bs *backendService) setup(ai cliutil.APIInfo) error {
	url, err := ai.DialArgs("v0")
	if err != nil {
		return err
	}

	wapi, closer, err := lclient.NewWalletRPCV0(bs.ctx, url, ai.AuthHeader())
	if err != nil {
		return err
	}

	bs.unsetReady()
	defer bs.setReady()

	bs.wallet = wapi
	bs.walletCloser = closer
	bs.wallet = wallet.NewAuthorizedWallet(bs.wallet)
	bs.wallet = api.PermissionedWalletAPI(bs.wallet)
	bs.rpc.Register("Filecoin", bs.wallet)
	bs.serviceRouter.Handle("/rpc/v0", bs.rpc)

	return nil
}

func (bs *backendService) setReady() {
	bs.readyMu.Lock()
	defer bs.readyMu.Unlock()
	bs.ready = true
}

func (bs *backendService) isReady() bool {
	bs.readyMu.Lock()
	defer bs.readyMu.Unlock()
	return bs.ready
}

func (bs *backendService) unsetReady() {
	bs.readyMu.Lock()
	defer bs.readyMu.Unlock()
	bs.ready = false
}

func (bs *backendService) close() {
	// just in case
	bs.unsetReady()
	bs.walletCloser()
}

var cmdBackend = &cli.Command{
	Name:  "backend",
	Usage: "backend service for secure wallet",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "jwt-secret-path",
			Usage:   "location of the jwt secret for signing and verifing jwt tokens",
			EnvVars: []string{"SECURE_WALLET_JWT_SECRET_PATH"},
			Value:   "./jwt-backend.jwts",
		},
	},
	Subcommands: []*cli.Command{
		{
			Name:  "token",
			Usage: "manage backend tokens",
			Subcommands: []*cli.Command{
				{
					Name:  "inspect",
					Usage: "dump the payload of a jwt token",
					Flags: []cli.Flag{},
					Action: func(cctx *cli.Context) error {
						var payload access.JwtPayload
						if err := jwtutil.DecodePayload([]byte(cctx.Args().First()), &payload); err != nil {
							return err
						}

						formatted, err := json.MarshalIndent(payload, "", "  ")
						if err != nil {
							return err
						}

						fmt.Printf("%s\n", string(formatted))

						return nil
					},
				},
				{
					Name:  "create",
					Usage: "create a token to allow access to a list of wallets",
					Flags: []cli.Flag{
						&cli.BoolFlag{
							Name:  "global-read",
							Value: false,
							Usage: "set the global read bit to enable this token to read all wallets",
						},
						&cli.BoolFlag{
							Name:  "read",
							Value: false,
							Usage: "add read permissions to the token",
						},
						&cli.BoolFlag{
							Name:  "write",
							Value: false,
							Usage: "add write permissions to the token",
						},
						&cli.BoolFlag{
							Name:  "sign",
							Value: false,
							Usage: "add sign permissions to the token",
						},
						&cli.BoolFlag{
							Name:  "admin",
							Value: false,
							Usage: "add admin permissions to the token",
						},
					},
					Action: func(cctx *cli.Context) error {
						walletAddrs := []address.Address{}

						for _, strAddr := range cctx.Args().Slice() {
							addr, err := address.NewFromString(strAddr)
							if err != nil {
								return err
							}

							walletAddrs = append(walletAddrs, addr)

						}

						perms := []auth.Permission{}

						if cctx.Bool("read") || cctx.Bool("global-read") {
							perms = append(perms, api.PermRead)
						}

						if cctx.Bool("write") {
							perms = append(perms, api.PermWrite)
						}

						if cctx.Bool("sign") {
							perms = append(perms, api.PermSign)
						}

						if cctx.Bool("admin") {
							perms = append(perms, api.PermAdmin)
						}

						p := access.JwtPayload{
							GlobalRead: cctx.Bool("global-read"),
							Access:     walletAddrs,
							Allow:      perms,
						}

						sl := access.NewSecretLoader(cctx.String("jwt-secret-path"), time.Minute)
						sd := access.NewApiSecretDecoder(sl)
						_, authKey, err := sd.Get()
						if err != nil {
							return err
						}

						k, err := jwt.Sign(&p, (*jwt.HMACSHA)(authKey))
						if err != nil {
							return xerrors.Errorf("jwt sign: %w", err)
						}

						fmt.Println(string(k))

						return nil
					},
				},
			},
		},
		{
			Name:  "client",
			Usage: "client for talking to the secure wallet backend service",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "backend-api",
					Usage:   "host and port of backend service api",
					EnvVars: []string{"SECURE_WALLET_BACKEND_API"},
					Value:   "http://127.0.0.1:9876",
				},
				&cli.StringFlag{
					Name:    "jwt-token-path",
					Usage:   "location of the jwt token for api requests",
					EnvVars: []string{"SECURE_WALLET_JWT_TOKEN_PATH"},
					Value:   "./jwt.token",
				},
				&cli.StringFlag{
					Name:    "api-info",
					Usage:   "classic api info flag: <token>:<api-endpoint>",
					EnvVars: []string{"SECURE_WALLET_API_INFO"},
					Hidden:  true,
				},
			},
			Before: func(cctx *cli.Context) error {
				if cctx.IsSet("api-info") {
					return nil
				}

				sl := access.NewSecretLoader(cctx.String("jwt-token-path"), time.Minute)
				_, secret, err := sl.Get()
				if err != nil {
					return err
				}

				apiInfo := fmt.Sprintf("%s:%s", string(secret), cctx.String("backend-api"))
				return cctx.Set("api-info", apiInfo)
			},
			Subcommands: clientCommands,
		},
		{
			Name:  "run",
			Usage: "backend service for secure wallet",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "lotus-wallet-api",
					Usage:   "host and port of backing wallet store",
					EnvVars: []string{"SECURE_WALLET_LOTUS_WALLET_API"},
					Value:   "http://localhost:1777",
				},
				&cli.StringFlag{
					Name:    "service-listen",
					Usage:   "host and port to listen on",
					EnvVars: []string{"SECURE_WALLET_BACKEND_SERVICE_LISTEN"},
					Value:   "localhost:9876",
				},
				&cli.StringFlag{
					Name:    "operator-listen",
					Usage:   "host and port to listen on",
					EnvVars: []string{"SECURE_WALLET_BACKEND_OPERATOR_LISTEN"},
					Value:   "localhost:6060",
				},
			},
			Action: func(cctx *cli.Context) error {
				ctx, cancelFunc := context.WithCancel(context.Background())
				ctx = context.WithValue(ctx, versionKey{}, build.Version())

				signalChan := make(chan os.Signal, 1)
				signal.Notify(signalChan, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)

				s := backendService{
					ctx:            ctx,
					serviceRouter:  mux.NewRouter(),
					operatorRouter: mux.NewRouter(),
					rpc:            jsonrpc.NewServer(),
				}

				s.setup(cliutil.ParseApiInfo(cctx.String("lotus-wallet-api")))
				sl := access.NewSecretLoader(cctx.String("jwt-secret-path"), time.Minute)
				sd := access.NewApiSecretDecoder(sl)

				authVerify := func(ctx context.Context, token string) (access.JwtPayload, error) {
					var payload access.JwtPayload
					_, authKey, err := sd.Get()
					if err != nil {
						return access.JwtPayload{}, xerrors.Errorf("JWT Verification failed: %w", err)
					}

					if _, err := jwt.Verify([]byte(token), (*jwt.HMACSHA)(authKey), &payload); err != nil {
						return access.JwtPayload{}, xerrors.Errorf("JWT Verification failed: %w", err)
					}

					return payload, nil
				}

				authHandler := &access.Handler{
					Verify: authVerify,
					Next:   s.serviceRouter.ServeHTTP,
				}

				svr := &http.Server{
					Addr:    cctx.String("service-listen"),
					Handler: authHandler,
					BaseContext: func(listener net.Listener) context.Context {
						return context.Background()
					},
				}

				go func() {
					err := svr.ListenAndServe()
					switch err {
					case nil:
					case http.ErrServerClosed:
						logging.Logger.Infow("server closed")
					case context.Canceled:
						logging.Logger.Infow("context cancled")
					default:
						logging.Logger.Errorw("error shutting down service server", "err", err)
					}
				}()

				s.operatorRouter.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)

				s.operatorRouter.HandleFunc("/liveness", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})

				s.operatorRouter.HandleFunc("/readiness", func(w http.ResponseWriter, r *http.Request) {
					isReady := s.isReady()

					if isReady {
						w.WriteHeader(http.StatusOK)
					} else {
						w.WriteHeader(http.StatusServiceUnavailable)
					}
				})

				osvr := http.Server{
					Addr:    cctx.String("operator-listen"),
					Handler: s.operatorRouter,
				}

				go func() {
					err := osvr.ListenAndServe()
					switch err {
					case nil:
					case http.ErrServerClosed:
						logging.Logger.Infow("server closed")
					case context.Canceled:
						logging.Logger.Infow("context cancled")
					default:
						logging.Logger.Errorw("error shutting down internal server", "err", err)
					}
				}()

				<-signalChan

				s.unsetReady()

				t := time.NewTimer(svrShutdownTimeout)

				shutdownChan := make(chan error)
				go func() {
					shutdownChan <- svr.Shutdown(ctx)
				}()

				select {
				case err := <-shutdownChan:
					if err != nil {
						logging.Logger.Errorw("shutdown finished with an error", "err", err)
					} else {
						logging.Logger.Infow("shutdown finished successfully")
					}
				case <-t.C:
					logging.Logger.Infow("shutdown timed out")
				}

				cancelFunc()
				time.Sleep(ctxCancelWait)

				logging.Logger.Infow("closing down database connections")

				s.close()

				if err := osvr.Shutdown(ctx); err != nil {
					switch err {
					case nil:
					case http.ErrServerClosed:
						logging.Logger.Infow("server closed")
					case context.Canceled:
						logging.Logger.Infow("context cancled")
					default:
						logging.Logger.Errorw("error shutting down operator server", "err", err)
					}
				}

				logging.Logger.Infow("existing")

				return nil
			},
		},
	},
}

func getCliClient(ctx context.Context, cctx *cli.Context) (lapi.Wallet, jsonrpc.ClientCloser, error) {
	ai := cliutil.ParseApiInfo(cctx.String("api-info"))
	url, err := ai.DialArgs("v0")
	if err != nil {
		return nil, func() {}, err
	}

	return lclient.NewWalletRPCV0(ctx, url, ai.AuthHeader())
}
