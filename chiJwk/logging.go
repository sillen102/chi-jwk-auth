package chiJwk

import (
    "fmt"
)

type Logger interface {
    Info(msg string, keysAndValues ...any)
    Error(err error, msg string, keysAndValues ...any)
    Debug(msg string, keysAndValues ...any)
}

// StdLogger is a simple logger that writes to stdout. It is the default logger and implements the Logger interface.
// It is not recommended for production use. It is recommended to use a more robust logger
// such as logrus or zap. This logger is provided as a convenience for users who do not want
// to use a more robust logger.
type StdLogger struct {
}

func NewStdLogger() StdLogger {
    return StdLogger{}
}

func (l StdLogger) Info(msg string, keysAndValues ...any) {
    fmt.Printf("INFO: %s: %v \n", msg, keysAndValues)
}

func (l StdLogger) Error(err error, msg string, keysAndValues ...any) {
    fmt.Printf("ERROR: %s: %v: %v\n", msg, keysAndValues, err)
}

func (l StdLogger) Debug(msg string, keysAndValues ...any) {
    fmt.Printf("DEBUG: %s: %v\n", msg, keysAndValues)
}
