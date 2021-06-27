module github.com/travisperson/secure-wallet

go 1.16

require (
	github.com/filecoin-project/go-address v0.0.5
	github.com/filecoin-project/go-jsonrpc v0.1.4-0.20210217175800-45ea43ac2bec
	github.com/filecoin-project/go-state-types v0.1.1-0.20210506134452-99b279731c48
	github.com/filecoin-project/lotus v1.9.0
	github.com/gbrlsnchs/jwt/v3 v3.0.0
	github.com/gorilla/mux v1.8.0
	github.com/prometheus/common v0.10.0
	github.com/urfave/cli/v2 v2.3.0
	go.uber.org/zap v1.17.0
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
)

replace github.com/filecoin-project/filecoin-ffi => github.com/filecoin-project/ffi-stub v0.1.0
