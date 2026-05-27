/*

Warpnet - Decentralized Social Network
Copyright (C) 2025 Vadim Filin, https://github.com/Warp-net,
<github.com.mecdy@passmail.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

WarpNet is provided "as is" without warranty of any kind, either expressed or implied.
Use at your own risk. The maintainers shall not be liable for any damages or data loss
resulting from the use or misuse of this software.
*/

// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package aliastransport

import (
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/transport"
)

// NewFactory returns a constructor suitable for libp2p.Transport(...). The
// libp2p config wires in the Upgrader and Host from its fx graph; privKey
// and warpID are captured in the closure.
//
// Example:
//
//	libp2p.New(libp2p.Transport(aliastransport.NewFactory(priv, warpID)))
func NewFactory(privKey crypto.PrivKey, warpID string) func(transport.Upgrader, host.Host) (*Transport, error) {
	return func(upgrader transport.Upgrader, h host.Host) (*Transport, error) {
		return New(upgrader, h, privKey, warpID)
	}
}
