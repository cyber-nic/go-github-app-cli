package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

type ctxLogger struct{}

func newLogger(logLevel string) *log.Logger {
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stdout)
		logger = level.NewFilter(logger, level.Allow(level.ParseDefault(logLevel, level.InfoValue())))
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
		level.Debug(logger).Log("msg", "debug enabled")
	}
	return &logger
}

// ContextWithLogger adds logger to context
func contextWithLogger(ctx context.Context, l *log.Logger) context.Context {
	return context.WithValue(ctx, ctxLogger{}, l)
}

func loggerFromContext(ctx context.Context) log.Logger {
	if l, ok := ctx.Value(ctxLogger{}).(*log.Logger); ok {
		return *l
	}

	w := log.NewSyncWriter(os.Stderr)
	logger := log.NewLogfmtLogger(w)
	return logger
}

// https://www.jvt.me/posts/2023/03/11/go-debug-http/

type loggingTransport struct{}

func (s *loggingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	bytes, _ := httputil.DumpRequestOut(r, true)

	resp, err := http.DefaultTransport.RoundTrip(r)
	// err is returned after dumping the response

	respBytes, _ := httputil.DumpResponse(resp, true)
	bytes = append(bytes, respBytes...)

	fmt.Printf("%s\n", bytes)

	return resp, err
}
