package chiJwk

import (
    "context"
    "os"

    "go.uber.org/zap"
)

const LogCtxKey = "log"

var logger *zap.Logger

func FromCtx(ctx context.Context) *zap.Logger {
    if l, ok := ctx.Value(LogCtxKey).(*zap.Logger); ok {
        return l
    } else {
        return Get()
    }
}

func Get() *zap.Logger {
    if logger == nil {
        switch os.Getenv("ENVIRONMENT") {
        case "dev", "development":
            logger, _ = zap.NewProduction()
        default:
            logger, _ = zap.NewProduction()
        }
    }
    defer func(logger *zap.Logger) {
        _ = logger.Sync()
    }(logger)
    return logger
}
