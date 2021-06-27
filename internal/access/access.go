package access

import (
	"context"
	"net/http"
	"strings"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-jsonrpc/auth"
	"github.com/prometheus/common/log"
)

type accessKey int

var accessCtxKey accessKey = 0
var globalReadCtxKey accessKey = 1

func WithAccess(ctx context.Context, addrs []address.Address) context.Context {
	return context.WithValue(ctx, accessCtxKey, addrs)
}

func HasAccess(ctx context.Context, addr address.Address) bool {
	callerAccess, ok := ctx.Value(accessCtxKey).([]address.Address)
	if !ok {
		callerAccess = []address.Address{}
	}

	for _, wallet := range callerAccess {
		if wallet == addr {
			return true
		}
	}
	return false

}

func WithGlobalRead(ctx context.Context, globalRead bool) context.Context {
	return context.WithValue(ctx, globalReadCtxKey, globalRead)
}

func GetGlobalRead(ctx context.Context) bool {
	callerGlobalRead, ok := ctx.Value(globalReadCtxKey).(bool)
	if !ok {
		callerGlobalRead = false
	}

	return callerGlobalRead
}

func GetAccess(ctx context.Context) []address.Address {
	callerAccess, ok := ctx.Value(accessCtxKey).([]address.Address)
	if !ok {
		callerAccess = []address.Address{}
	}

	return callerAccess
}

type Handler struct {
	Verify func(ctx context.Context, token string) (JwtPayload, error)
	Next   http.HandlerFunc
}

type JwtPayload struct {
	GlobalRead bool
	Access     []address.Address
	Allow      []auth.Permission
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := r.Header.Get("Authorization")
	if token == "" {
		token = r.FormValue("token")
		if token != "" {
			token = "Bearer " + token
		}
	}

	if token != "" {
		if !strings.HasPrefix(token, "Bearer ") {
			log.Warn("missing Bearer prefix in auth header")
			w.WriteHeader(401)
			return
		}
		token = strings.TrimPrefix(token, "Bearer ")

		payload, err := h.Verify(ctx, token)
		if err != nil {
			log.Warnf("JWT Verification failed (originating from %s): %s", r.RemoteAddr, err)
			w.WriteHeader(401)
			return
		}

		ctx = WithAccess(ctx, payload.Access)
		ctx = WithGlobalRead(ctx, payload.GlobalRead)
		ctx = auth.WithPerm(ctx, payload.Allow)
	}

	h.Next(w, r.WithContext(ctx))
}
