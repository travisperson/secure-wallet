package logging

import (
	"go.uber.org/zap"
)

var Logger *zap.SugaredLogger

func init() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}

	Logger = logger.Sugar()
}
