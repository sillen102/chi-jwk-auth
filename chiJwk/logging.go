package chiJwk

type Logger interface {
    Print(v ...any)
    Fatal(v ...any)
    Panic(v ...any)
}
