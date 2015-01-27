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

var server *ServerInfo

func run(configFile string) {
	sleepInterval := 60

	config := readConfigFile(configFile)
	udpServer := config.Server.newUDPServer()
	udpServer.start()

	for {
		udpServer.log.Debug("Main thread sleeping for %d seconds\n", sleepInterval)
		time.Sleep(time.Duration(sleepInterval) * time.Second)
	}
}

func main() {

	sigint.ListenForSIGINT(func() {
		server.Shutdown()
	})

	app := getApp()
	app.Run(os.Args)

}
