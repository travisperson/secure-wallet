package wallet

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/crypto"
	lapi "github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/chain/types"

	"github.com/travisperson/secure-wallet/internal/access"
	"github.com/travisperson/secure-wallet/internal/logging"
)

var _ lapi.Wallet = &AuthorizedWallet{}

type AuthorizedWallet struct {
	wallet lapi.Wallet
}

func NewAuthorizedWallet(w lapi.Wallet) *AuthorizedWallet {
	return &AuthorizedWallet{
		wallet: w,
	}
}

func (w *AuthorizedWallet) WalletNew(_ context.Context, _ types.KeyType) (address.Address, error) {
	return address.Undef, xerrors.Errorf("WalletNew is not supported")
}

func (w *AuthorizedWallet) WalletHas(ctx context.Context, addr address.Address) (bool, error) {
	if !access.GetGlobalRead(ctx) && !access.HasAccess(ctx, addr) {
		return false, nil
	}

	return w.wallet.WalletHas(ctx, addr)
}

func (w *AuthorizedWallet) WalletList(ctx context.Context) ([]address.Address, error) {
	if access.GetGlobalRead(ctx) {
		return w.wallet.WalletList(ctx)
	}

	access := access.GetAccess(ctx)
	addrs := []address.Address{}

	for _, wallet := range access {
		ok, _ := w.wallet.WalletHas(ctx, wallet)
		logging.Logger.Infow("listing_has", "addr", wallet, "ok", ok)
		if ok {
			addrs = append(addrs, wallet)
		}
	}

	return addrs, nil
}

func (w *AuthorizedWallet) WalletSign(ctx context.Context, signer address.Address, toSign []byte, meta lapi.MsgMeta) (*crypto.Signature, error) {
	ok, err := w.WalletHas(ctx, signer)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, xerrors.Errorf("signer address does not exist")
	}

	return w.wallet.WalletSign(ctx, signer, toSign, meta)
}

func (w *AuthorizedWallet) WalletExport(_ context.Context, _ address.Address) (*types.KeyInfo, error) {
	return nil, xerrors.Errorf("WalletExport is not supported")
}

func (w *AuthorizedWallet) WalletImport(_ context.Context, _ *types.KeyInfo) (address.Address, error) {
	return address.Undef, xerrors.Errorf("WalletImport is not supported")
}

func (w *AuthorizedWallet) WalletDelete(_ context.Context, _ address.Address) error {
	return xerrors.Errorf("WalletDelete is not supported")
}
