package api

import (
	"context"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/crypto"
	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/chain/types"
)

type WalletStruct struct {
	Internal struct {
		WalletDelete func(p0 context.Context, p1 address.Address) error                                                 `perm:"admin"`
		WalletExport func(p0 context.Context, p1 address.Address) (*types.KeyInfo, error)                               `perm:"admin"`
		WalletHas    func(p0 context.Context, p1 address.Address) (bool, error)                                         `perm:"read"`
		WalletImport func(p0 context.Context, p1 *types.KeyInfo) (address.Address, error)                               `perm:"write"`
		WalletList   func(p0 context.Context) ([]address.Address, error)                                                `perm:"read"`
		WalletNew    func(p0 context.Context, p1 types.KeyType) (address.Address, error)                                `perm:"write"`
		WalletSign   func(p0 context.Context, p1 address.Address, p2 []byte, p3 api.MsgMeta) (*crypto.Signature, error) `perm:"sign"`
	}
}

func (s *WalletStruct) WalletDelete(p0 context.Context, p1 address.Address) error {
	return s.Internal.WalletDelete(p0, p1)
}

func (s *WalletStruct) WalletExport(p0 context.Context, p1 address.Address) (*types.KeyInfo, error) {
	return s.Internal.WalletExport(p0, p1)
}

func (s *WalletStruct) WalletHas(p0 context.Context, p1 address.Address) (bool, error) {
	return s.Internal.WalletHas(p0, p1)
}

func (s *WalletStruct) WalletImport(p0 context.Context, p1 *types.KeyInfo) (address.Address, error) {
	return s.Internal.WalletImport(p0, p1)
}

func (s *WalletStruct) WalletList(p0 context.Context) ([]address.Address, error) {
	return s.Internal.WalletList(p0)
}

func (s *WalletStruct) WalletNew(p0 context.Context, p1 types.KeyType) (address.Address, error) {
	return s.Internal.WalletNew(p0, p1)
}

func (s *WalletStruct) WalletSign(p0 context.Context, p1 address.Address, p2 []byte, p3 api.MsgMeta) (*crypto.Signature, error) {
	return s.Internal.WalletSign(p0, p1, p2, p3)
}
