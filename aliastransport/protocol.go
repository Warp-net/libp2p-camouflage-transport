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

// Package aliastransport implements a libp2p transport that hides a peer's
// real network address behind a hex alias ("WarpID"). A peer registers its
// WarpID on a relay; dialers reach the peer by addressing
//
//	/p2p/<relayID>/warpid/<warpID>/p2p/<peerID>
//
// without ever learning the peer's IP. The relay knows the mapping but sees
// only encrypted traffic between dialer and listener thanks to the libp2p
// security upgrade (e.g. Noise) that runs end-to-end inside the forwarded
// stream.
package aliastransport

import (
	"encoding/hex"
	"errors"
	"fmt"

	ma "github.com/multiformats/go-multiaddr"
)

// P_WARPID is the multiaddr protocol code for the /warpid/<hex> component.
// 0x0300 sits in the private-use range and does not collide with any
// upstream multicodec entry as of go-multiaddr v0.16.
const P_WARPID = 0x0300

// WarpIDName is the textual protocol name (`/warpid/...`).
const WarpIDName = "warpid"

// WarpIDByteLen is the fixed length of a decoded WarpID. The textual form
// is hex-encoded, so the string is always WarpIDByteLen*2 characters.
const WarpIDByteLen = 32

var errInvalidWarpID = errors.New("warpid: invalid value")

// init registers the /warpid/ multiaddr protocol. It runs on package import,
// which makes the protocol available everywhere the transport is linked in.
// Calling AddProtocol twice with the same code returns an error; we swallow
// it because identical re-registration is harmless.
func init() {
	transcoder := ma.NewTranscoderFromFunctions(warpIDStrToBytes, warpIDBytesToStr, warpIDValidate)
	proto := ma.Protocol{
		Name:       WarpIDName,
		Code:       P_WARPID,
		VCode:      ma.CodeToVarint(P_WARPID),
		Size:       WarpIDByteLen * 8,
		Transcoder: transcoder,
	}
	_ = ma.AddProtocol(proto)
}

func warpIDStrToBytes(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidWarpID, err)
	}
	if len(b) != WarpIDByteLen {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", errInvalidWarpID, WarpIDByteLen, len(b))
	}
	return b, nil
}

func warpIDBytesToStr(b []byte) (string, error) {
	if len(b) != WarpIDByteLen {
		return "", fmt.Errorf("%w: expected %d bytes, got %d", errInvalidWarpID, WarpIDByteLen, len(b))
	}
	return hex.EncodeToString(b), nil
}

func warpIDValidate(b []byte) error {
	if len(b) != WarpIDByteLen {
		return fmt.Errorf("%w: expected %d bytes, got %d", errInvalidWarpID, WarpIDByteLen, len(b))
	}
	return nil
}
