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

package camouflage

import (
	"crypto/rand"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

const defaultFragmentSize = 2

// spoofSource is the minimal contract SpoofConn requires from its
// underlying source: byte transport plus deadline handling. Both
// manet.Conn (raw TCP path) and network.Stream (relay-proxied alias
// path) satisfy it, so SpoofConn can wrap either uniformly.
type spoofSource interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// SpoofConn wraps a stream-like source and transparently splits Write
// calls into small segments during the handshake phase (the first
// handshakeLen bytes). After the handshake, writes pass through
// without modification.
//
// It implements manet.Conn directly, so it flows through the camouflage
// listener + upgrader pipeline regardless of whether the bytes ride on
// raw TCP or on a relay-proxied libp2p stream.
type SpoofConn struct {
	src    spoofSource
	local  ma.Multiaddr
	remote ma.Multiaddr

	mu           sync.Mutex
	bytesWritten int
	fragmentSize int
	handshakeLen int
	maxDelay     time.Duration
}

var _ manet.Conn = (*SpoofConn)(nil)

// NewSpoofConn wraps a manet.Conn. If the argument is already a
// *SpoofConn (because the alias path pre-wrapped a network.Stream),
// the same SpoofConn is returned unchanged — that way the camouflage
// listener pipeline can call NewSpoofConn on every accepted conn
// uniformly without double-fragmenting.
func NewSpoofConn(conn manet.Conn, fragmentSize, handshakeLen int, maxDelay time.Duration) *SpoofConn {
	if sc, ok := conn.(*SpoofConn); ok {
		return sc
	}
	return &SpoofConn{
		src:          conn,
		local:        conn.LocalMultiaddr(),
		remote:       conn.RemoteMultiaddr(),
		fragmentSize: fragmentSize,
		handshakeLen: handshakeLen,
		maxDelay:     maxDelay,
	}
}

// NewSpoofConnFromStream wraps a libp2p network.Stream as a SpoofConn.
// Used by the alias path; local and remote are the multiaddrs that
// should be exposed via manet.Conn methods.
func NewSpoofConnFromStream(s network.Stream, local, remote ma.Multiaddr, fragmentSize, handshakeLen int, maxDelay time.Duration) *SpoofConn {
	return &SpoofConn{
		src:          s,
		local:        local,
		remote:       remote,
		fragmentSize: fragmentSize,
		handshakeLen: handshakeLen,
		maxDelay:     maxDelay,
	}
}

func (c *SpoofConn) Read(p []byte) (int, error)         { return c.src.Read(p) }
func (c *SpoofConn) Close() error                       { return c.src.Close() }
func (c *SpoofConn) SetDeadline(t time.Time) error      { return c.src.SetDeadline(t) }
func (c *SpoofConn) SetReadDeadline(t time.Time) error  { return c.src.SetReadDeadline(t) }
func (c *SpoofConn) SetWriteDeadline(t time.Time) error { return c.src.SetWriteDeadline(t) }

func (c *SpoofConn) LocalAddr() net.Addr {
	if a, ok := c.src.(interface{ LocalAddr() net.Addr }); ok {
		return a.LocalAddr()
	}
	return spoofAddr(maStr(c.local))
}

func (c *SpoofConn) RemoteAddr() net.Addr {
	if a, ok := c.src.(interface{ RemoteAddr() net.Addr }); ok {
		return a.RemoteAddr()
	}
	return spoofAddr(maStr(c.remote))
}

func (c *SpoofConn) LocalMultiaddr() ma.Multiaddr  { return c.local }
func (c *SpoofConn) RemoteMultiaddr() ma.Multiaddr { return c.remote }

type spoofAddr string

func (a spoofAddr) Network() string { return "camouflage" }
func (a spoofAddr) String() string  { return string(a) }

func maStr(a ma.Multiaddr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// Write fragments b into small segments if the handshake phase is still
// active; otherwise it delegates directly to the underlying source.
func (c *SpoofConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	pastHandshake := c.bytesWritten >= c.handshakeLen
	c.mu.Unlock()

	if pastHandshake {
		return c.src.Write(b)
	}

	return c.fragmentedWrite(b)
}

func (c *SpoofConn) fragmentedWrite(b []byte) (int, error) {
	fragSize := c.fragmentSize
	if fragSize <= 0 {
		fragSize = defaultFragmentSize
	}

	total := 0
	for len(b) > 0 {
		c.mu.Lock()
		pastHandshake := c.bytesWritten >= c.handshakeLen
		c.mu.Unlock()

		if pastHandshake {
			// Past handshake: write-all loop for the remainder.
			for len(b) > 0 {
				n, err := c.src.Write(b)
				c.mu.Lock()
				c.bytesWritten += n
				c.mu.Unlock()
				total += n
				if n == 0 && err == nil {
					return total, io.ErrShortWrite
				}
				if err != nil {
					return total, err
				}
				b = b[n:]
			}
			return total, nil
		}

		size := min(fragSize, len(b))
		n, err := c.src.Write(b[:size])
		c.mu.Lock()
		c.bytesWritten += n
		c.mu.Unlock()
		total += n
		if n == 0 && err == nil {
			return total, io.ErrShortWrite
		}
		if err != nil {
			return total, err
		}
		b = b[n:]

		c.mu.Lock()
		stillHandshake := c.bytesWritten < c.handshakeLen
		c.mu.Unlock()
		if len(b) > 0 && stillHandshake {
			delay := randDuration(c.maxDelay)
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}
	return total, nil
}

// CloseRead forwards to the underlying source if supported.
func (c *SpoofConn) CloseRead() error {
	if cr, ok := c.src.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// CloseWrite forwards to the underlying source if supported.
func (c *SpoofConn) CloseWrite() error {
	if cw, ok := c.src.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func randDuration(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maximum)))
	if err != nil {
		return maximum / 2
	}
	return time.Duration(n.Int64())
}
