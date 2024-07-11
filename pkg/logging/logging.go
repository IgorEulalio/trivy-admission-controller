package logging

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var logger zerolog.Logger

func InitLogger() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
}

func Logger() zerolog.Logger {
	return logger
}
