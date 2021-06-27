package access

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/lotus/node/modules/dtypes"
	"github.com/gbrlsnchs/jwt/v3"
)

type SecretLoader interface {
	Get() (bool, []byte, error)
}

type FileSecretLoader struct {
	secretPath string
	secret     []byte
	secretMu   sync.Mutex

	expiryTime   time.Time
	expiryPeriod time.Duration
}

func NewSecretLoader(secretPath string, expiryPeriod time.Duration) *FileSecretLoader {
	return &FileSecretLoader{
		secretPath:   secretPath,
		expiryTime:   time.Now(),
		expiryPeriod: expiryPeriod,
	}
}

func (sl *FileSecretLoader) Get() (bool, []byte, error) {
	sl.secretMu.Lock()
	defer sl.secretMu.Unlock()

	secretBefore := sl.secret

	if time.Now().After(sl.expiryTime) {
		if err := sl.loadSecret(); err != nil {
			return false, nil, err
		}
	}

	return !bytes.Equal(secretBefore, sl.secret), sl.secret, nil
}

func (sl *FileSecretLoader) loadSecret() error {
	secret, err := os.ReadFile(sl.secretPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to stat secret: %w", err)
	} else if err != nil {
		return err
	}

	if bytes.Equal(sl.secret, secret) {
		return nil
	}

	sl.secret = secret
	sl.expiryTime = time.Now().Add(sl.expiryPeriod)

	return nil
}

type ApiSecretDecoder struct {
	secretLoader SecretLoader
	lastReturn   *dtypes.APIAlg
}

func NewApiSecretDecoder(secretLoader SecretLoader) *ApiSecretDecoder {
	return &ApiSecretDecoder{
		secretLoader: secretLoader,
	}
}

func (sd *ApiSecretDecoder) Get() (bool, *dtypes.APIAlg, error) {
	changed, secret, err := sd.secretLoader.Get()
	if err != nil {
		return false, sd.lastReturn, err
	}

	if !changed {
		return false, sd.lastReturn, nil
	}

	dst := make([]byte, hex.DecodedLen(len(secret)))

	if _, err := hex.Decode(dst, secret); err != nil {
		return false, nil, err
	}

	var ki types.KeyInfo
	if err := json.Unmarshal(dst, &ki); err != nil {
		return false, nil, err
	}

	sd.lastReturn = keyInfoToAPISecret(ki)

	return true, sd.lastReturn, nil
}

func keyInfoToAPISecret(ki types.KeyInfo) *dtypes.APIAlg {
	return (*dtypes.APIAlg)(jwt.NewHS256(ki.PrivateKey))
}
