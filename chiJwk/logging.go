package chiJwk

type Logger interface {
    Info(msg string, keysAndValues ...interface{})
    Error(err error, msg string, keysAndValues ...interface{})
    Debug(msg string, keysAndValues ...interface{})
}
