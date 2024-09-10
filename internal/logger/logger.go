package logger

import (
	"log"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	Level      string `json:"level,omitempty"      koanf:"level"`
	Stacktrace bool   `json:"stacktrace,omitempty" koanf:"stacktrace"`
}

// New creates a zap logger for console.
func New(cfg Config) *zap.Logger {
	var lvl zapcore.Level
	if err := lvl.Set(cfg.Level); err != nil {
		log.Printf("cannot parse log level %s: %s", cfg.Level, err)

		lvl = zapcore.WarnLevel
	}

	encoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	defaultCore := zapcore.NewCore(encoder, zapcore.Lock(zapcore.AddSync(os.Stderr)), lvl)
	cores := []zapcore.Core{
		defaultCore,
	}

	core := zapcore.NewTee(cores...)
	var zapOpts = make([]zap.Option, 0, 2)
	zapOpts = append(zapOpts, zap.AddCaller())

	if cfg.Stacktrace {
		zapOpts = append(zapOpts, zap.AddStacktrace(zap.ErrorLevel))
	}

	logger := zap.New(core, zapOpts...)

	return logger
}
