package client

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-jsonrpc"
	"github.com/filecoin-project/go-state-types/crypto"
	lapi "github.com/filecoin-project/lotus/api"
	lclient "github.com/filecoin-project/lotus/api/client"
	"github.com/filecoin-project/lotus/chain/types"
	cliutil "github.com/filecoin-project/lotus/cli/util"
	"github.com/travisperson/secure-wallet/api"
	"github.com/travisperson/secure-wallet/internal/access"
)

func NewWalletRPCV0(ctx context.Context, addr string, requestHeader http.Header) (lapi.Wallet, jsonrpc.ClientCloser, error) {
	var res api.WalletStruct
	closer, err := jsonrpc.NewMergeClient(ctx, addr, "Filecoin",
		[]interface{}{
			&res.Internal,
		},
		requestHeader,
	)

	return &res, closer, err
}

var _ lapi.Wallet = &jwtTokenLoaderClient{}

type jwtTokenLoaderClient struct {
	ctx          context.Context
	secretLoader access.SecretLoader
	lastClient   lapi.Wallet
	lastCloser   jsonrpc.ClientCloser
	lastMu       sync.Mutex
	addr         string
}

func NewJwtTokenLoaderWalletRPCV0(ctx context.Context, addr string, secretLoader access.SecretLoader) (lapi.Wallet, jsonrpc.ClientCloser, error) {
	r := &jwtTokenLoaderClient{
		secretLoader: secretLoader,
		ctx:          ctx,
		addr:         addr,
		lastCloser:   func() {},
	}

	if err := r.loadClient(); err != nil {
		return nil, func() {}, err
	}

	return r, func() {
		r.lastMu.Lock()
		defer r.lastMu.Unlock()
		r.lastCloser()
	}, nil
}

func (j *jwtTokenLoaderClient) loadClient() error {
	j.lastMu.Lock()
	defer j.lastMu.Unlock()

	changed, secret, err := j.secretLoader.Get()
	if err != nil {
		return err
	}

	if !changed {
		return nil
	}

	ai := cliutil.ParseApiInfo(fmt.Sprintf("%s:%s", string(secret), j.addr))

	url, err := ai.DialArgs("v0")
	if err != nil {
		return err
	}

	wapi, closer, err := lclient.NewWalletRPCV0(j.ctx, url, ai.AuthHeader())
	if err != nil {
		return err
	}

	j.lastCloser()

	j.lastClient = wapi
	j.lastCloser = closer

	return nil
}

func (j *jwtTokenLoaderClient) WalletNew(ctx context.Context, kt types.KeyType) (address.Address, error) {
	if err := j.loadClient(); err != nil {
		return address.Undef, err
	}

	return j.lastClient.WalletNew(ctx, kt)
}

func (j *jwtTokenLoaderClient) WalletHas(ctx context.Context, addr address.Address) (bool, error) {
	if err := j.loadClient(); err != nil {
		return false, err
	}

	return j.lastClient.WalletHas(ctx, addr)
}

func (j *jwtTokenLoaderClient) WalletList(ctx context.Context) ([]address.Address, error) {
	if err := j.loadClient(); err != nil {
		return []address.Address{}, err
	}

	return j.lastClient.WalletList(ctx)
}

func (j *jwtTokenLoaderClient) WalletSign(ctx context.Context, signer address.Address, toSign []byte, meta lapi.MsgMeta) (*crypto.Signature, error) {
	if err := j.loadClient(); err != nil {
		return nil, err
	}

	return j.lastClient.WalletSign(ctx, signer, toSign, meta)
}

func (j *jwtTokenLoaderClient) WalletExport(ctx context.Context, addr address.Address) (*types.KeyInfo, error) {
	if err := j.loadClient(); err != nil {
		return nil, err
	}
	return j.lastClient.WalletExport(ctx, addr)
}

func (j *jwtTokenLoaderClient) WalletImport(ctx context.Context, ki *types.KeyInfo) (address.Address, error) {
	if err := j.loadClient(); err != nil {
		return address.Undef, err
	}
	return j.lastClient.WalletImport(ctx, ki)
}

func (j *jwtTokenLoaderClient) WalletDelete(ctx context.Context, addr address.Address) error {
	if err := j.loadClient(); err != nil {
		return err
	}
	return j.lastClient.WalletDelete(ctx, addr)
}
