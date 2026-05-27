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
	"fmt"
	"io"
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// streamConn wraps a libp2p network.Stream as a manet.Conn so the libp2p
// upgrader can run Noise + a stream muxer over it. The reader is overridable
// because the resolve handshake leaves leftover bytes in a bufio reader
// that must not be lost when piping begins.
type streamConn struct {
	stream network.Stream
	reader io.Reader

	local  ma.Multiaddr
	remote ma.Multiaddr
}

var _ manet.Conn = (*streamConn)(nil)

func newStreamConn(s network.Stream, reader io.Reader, local, remote ma.Multiaddr) *streamConn {
	if reader == nil {
		reader = s
	}
	return &streamConn{
		stream: s,
		reader: reader,
		local:  local,
		remote: remote,
	}
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *streamConn) Close() error                { return c.stream.Close() }

func (c *streamConn) LocalAddr() net.Addr  { return aliasNetAddr{label: c.local.String()} }
func (c *streamConn) RemoteAddr() net.Addr { return aliasNetAddr{label: c.remote.String()} }

func (c *streamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

func (c *streamConn) LocalMultiaddr() ma.Multiaddr  { return c.local }
func (c *streamConn) RemoteMultiaddr() ma.Multiaddr { return c.remote }

// aliasNetAddr satisfies net.Addr for the wrapped stream. The libp2p
// upgrader only inspects the string form, so embedding the multiaddr text
// keeps logs and debug dumps useful.
type aliasNetAddr struct {
	label string
}

func (a aliasNetAddr) Network() string { return "libp2p-warpid" }
func (a aliasNetAddr) String() string  { return a.label }

// errClosedListener is returned from Accept when the Listener has been
// closed. Mirrors the convention used by other libp2p transports.
var errClosedListener = fmt.Errorf("warpid listener closed")
