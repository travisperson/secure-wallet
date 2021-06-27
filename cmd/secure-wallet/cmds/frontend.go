package cmds

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/filecoin-project/go-jsonrpc"
	lapi "github.com/filecoin-project/lotus/api"
	"github.com/gorilla/mux"
	"github.com/urfave/cli/v2"

	"github.com/travisperson/secure-wallet/api/client"
	"github.com/travisperson/secure-wallet/build"
	"github.com/travisperson/secure-wallet/internal/access"
	"github.com/travisperson/secure-wallet/internal/logging"
)

type frontendService struct {
	ctx            context.Context
	serviceRouter  *mux.Router
	operatorRouter *mux.Router
	rpc            *jsonrpc.RPCServer
	wallet         lapi.Wallet
	walletCloser   jsonrpc.ClientCloser

	ready   bool
	readyMu sync.Mutex
}

func (bs *frontendService) setup(addr string, sl access.SecretLoader) error {
	wapi, closer, err := client.NewJwtTokenLoaderWalletRPCV0(bs.ctx, addr, sl)
	if err != nil {
		return err
	}

	bs.unsetReady()
	defer bs.setReady()

	bs.wallet = wapi
	bs.walletCloser = closer
	bs.rpc.Register("Filecoin", bs.wallet)
	bs.serviceRouter.Handle("/rpc/v0", bs.rpc)

	return nil
}

func (bs *frontendService) setReady() {
	bs.readyMu.Lock()
	defer bs.readyMu.Unlock()
	bs.ready = true
}

func (bs *frontendService) isReady() bool {
	bs.readyMu.Lock()
	defer bs.readyMu.Unlock()
	return bs.ready
}

func (bs *frontendService) unsetReady() {
	bs.readyMu.Lock()
	defer bs.readyMu.Unlock()
	bs.ready = false
}

func (bs *frontendService) close() {
	bs.unsetReady()
	bs.walletCloser()
}

var cmdFrontend = &cli.Command{
	Name:  "frontend",
	Usage: "frontend service for secure wallet",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "jwt-token-path",
			Usage:   "location of the jwt token for api requests",
			EnvVars: []string{"SECURE_WALLET_JWT_TOKEN_PATH"},
			Value:   "./jwt.token",
		},
	},
	Subcommands: []*cli.Command{
		{
			Name:  "client",
			Usage: "client for talking to the frontend service, or any lotus wallet service",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "lotus-wallet-api",
					Usage:   "host and port of frontend service api",
					EnvVars: []string{"SECURE_WALLET_LOTUS_WALLET_API"},
					Value:   "http://127.0.0.1:6789",
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

				apiInfo := fmt.Sprintf("%s", cctx.String("lotus-wallet-api"))
				return cctx.Set("api-info", apiInfo)
			},
			Subcommands: clientCommands,
		},
		{
			Name:  "run",
			Usage: "start the lotus wallet proxy service",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "backend-api",
					Usage:   "host and port of backend service api",
					EnvVars: []string{"SECURE_WALLET_BACKEND_API"},
					Value:   "http://127.0.0.1:9876",
				},
				&cli.StringFlag{
					Name:    "service-listen",
					Usage:   "host and port to listen on",
					EnvVars: []string{"SECURE_WALLET_FRONTEND_SERVICE_LISTEN"},
					Value:   "localhost:6789",
				},
				&cli.StringFlag{
					Name:    "operator-listen",
					Usage:   "host and port to listen on",
					EnvVars: []string{"SECURE_WALLET_FRONTEND_OPERATOR_LISTEN"},
					Value:   "localhost:7070",
				},
			},
			Action: func(cctx *cli.Context) error {
				ctx, cancelFunc := context.WithCancel(context.Background())
				ctx = context.WithValue(ctx, versionKey{}, build.Version())

				signalChan := make(chan os.Signal, 1)
				signal.Notify(signalChan, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)

				s := frontendService{
					ctx:            ctx,
					serviceRouter:  mux.NewRouter(),
					operatorRouter: mux.NewRouter(),
					rpc:            jsonrpc.NewServer(),
				}

				sl := access.NewSecretLoader(cctx.String("jwt-token-path"), time.Minute)
				if err := s.setup(cctx.String("backend-api"), sl); err != nil {
					return err
				}

				svr := &http.Server{
					Addr:    cctx.String("service-listen"),
					Handler: s.serviceRouter,
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
