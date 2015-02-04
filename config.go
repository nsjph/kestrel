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
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/codegangsta/cli"
	"github.com/nsjph/cryptoauth"
	"io/ioutil"
	"net"
	"os"
)

// type tomlConfig struct {
// 	Server serverConfig
// }

// type serverConfig struct {
// 	Listen     string `toml:"listen"`
// 	Device     string `toml:"device"`
// 	PublicKey  string `toml:"public_key"`
// 	PrivateKey string `toml:"private_key"`
// 	IPv6       string `toml:"ipv6"`
// }

// getApp is used to configure the command-line defaults, arguments and flags of kestrel
//
// It uses the cli package from https://github.com/codegangsta/cli
func getApp() *cli.App {
	app := cli.NewApp()
	app.Name = "kestrel"
	app.Usage = "An experimental cjdns router"
	app.Author = "JPH"
	app.Email = "jph@hackworth.be"
	app.Version = "0.1.0a"
	app.Commands = []cli.Command{
		{
			Name:  "genconf",
			Usage: "generate a new config",
			Action: func(c *cli.Context) {
				generateConfig()
			},
		},
	}

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config, c",
			Value: "/etc/kestrel/kestrel.toml",
			Usage: "Config file location",
		},
	}

	app.Action = func(c *cli.Context) {

		//config := readConfigFile(c.String("config"))
		run(c.String("config"))
		println("hi!")
	}
	return app
}

// Reads the kestrel config file and decodes into tomlConfig
func readConfigFile(configPath string) TomlConfig {
	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error %s\n", err)
		os.Exit(1)
	}

	var conf TomlConfig
	_, err = toml.Decode(string(configData), &conf)
	check(err)
	return conf
}

// Checks that the config has the minimum info to start kestrel:
// - public key
// - private key
// - valid ipv6
// - valid listen address
func validateConfig(config TomlConfig) {

}

// Creates a new kestrel config and prints to stdout
func generateConfig() error {
	conf := TomlConfig{}
	keys, err := cryptoauth.NewIdentityKeys()
	checkFatal(err)
	conf.Server.IPv6 = keys.IPv6.String()
	conf.Server.PublicKey = fmt.Sprintf("%s.k", cryptoauth.Base32Encode(keys.PublicKey[:])[:52])
	conf.Server.PrivateKey = hex.EncodeToString(keys.PrivateKey[:])
	conf.Server.Listen = generateListenAddress()
	conf.Server.Device = "tun1"
	buf := new(bytes.Buffer)
	err = toml.NewEncoder(buf).Encode(conf)
	checkFatal(err)
	fmt.Println(buf.String())
	return nil
}

// Creates a local UDP IPv4 address host:port combination for kestrel to use
//
// By default, set to listen on all IPv4 interfaces (0.0.0.0)
// Will attempt to listen on a random high port temporarily and will assign this if successful.
//
// Returns a string in the format of "host:port", for example "0.0.0.0:30000"
func generateListenAddress() (listenAddress string) {
	addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
	check(err)
	conn, err := net.ListenUDP("udp4", addr)
	check(err)
	listenAddress = conn.LocalAddr().String()
	conn.Close()
	return listenAddress
}
