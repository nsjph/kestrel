// Copyright 2014 JPH <jph@hackworth.be>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"github.com/adampresley/sigint"
	"os"
	"time"
)

// http://guzalexander.com/2013/12/06/golang-channels-tutorial.html

// serverInfo struct contains:
// - tun device file handle,
// - udp network server connection
// - logger handle
// - goroutine descriptors
//
// These allow kestrel to shutdown() gracefully when it receives an
// interrupt or fatal erro
var server *ServerInfo

// config struct contains the variables from the main kestrel
// configuration file
//var config tomlConfig

//func start(config tomlConfig) {
func run(configFile string) {
	sleepInterval := 60

	config := readConfigFile(configFile)

	//startUDPServer(config.Server.Listen, &server)
	//initTunDevice(config, &server)

	//server = startServer(config)
	router := newRouter(&config)

	router.Log.Debug("Starting\n")

	router.Start()

	for {
		router.Log.Debug("Main thread sleeping for %d seconds\n", sleepInterval)
		//router.Log.Debug("Sleeping for %d seconds\n", sleepInterval)
		time.Sleep(time.Duration(sleepInterval) * time.Second)
	}
}

//ctrl-c interrupt code from http://adampresley.com/2014/12/15/handling-ctrl-c-in-go-command-line-applications.html
func main() {

	sigint.ListenForSIGINT(func() {
		//router.Log.Debug("Received SIGINT.\n")
		server.Shutdown()
	})

	app := getApp()
	app.Run(os.Args)

}
