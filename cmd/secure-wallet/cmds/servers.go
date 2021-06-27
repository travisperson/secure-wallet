package cmds

import "time"

var (
	routeTimeout       = 5 * time.Second
	svrShutdownTimeout = 1 * time.Second
	ctxCancelWait      = 3 * time.Second
)

type versionKey struct{}
