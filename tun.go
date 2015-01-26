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
	tun "github.com/nsjph/tun"
	"log"
)

func startTunDevice(config TomlConfig) *tun.Tun {

	log.Printf("starting tun device")

	tunDevice := tun.New()
	tunDevice.Open()
	tunDevice.SetupAddress(config.Server.IPv6, 1312)
	tunDevice.Start()

	return tunDevice
}
