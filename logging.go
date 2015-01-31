package main

import (
	"github.com/op/go-logging"
	"io"
	_ "os"
)

var logger = logging.MustGetLogger("kestrel")

var logFormat = logging.MustStringFormatter(
	"%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
)

// Returns a new logger with default configuration. Called when initializing a new router
func initLogger(program string, level logging.Level, output io.Writer) (log *logging.Logger) {

	//log = logging.MustGetLogger(program)
	backend := logging.NewLogBackend(output, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, logFormat)
	backendLevel := logging.AddModuleLevel(backend)
	backendLevel.SetLevel(level, "")

	logging.SetBackend(backendLevel, backendFormatter)

	return logger

}
