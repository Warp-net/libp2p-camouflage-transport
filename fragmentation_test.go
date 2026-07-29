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

package camouflage

import (
	"bytes"
	"net"
	"testing"
	"time"

	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captureConn struct {
	net.Conn
	writes [][]byte
}

func (c *captureConn) Write(b []byte) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	c.writes = append(c.writes, cp)
	return len(b), nil
}
func (c *captureConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return loopbackAddr() }
func (c *captureConn) RemoteAddr() net.Addr             { return loopbackAddr() }

func loopbackAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

func (c *captureConn) stream() []byte {
	var buf bytes.Buffer
	for _, w := range c.writes {
		buf.Write(w)
	}
	return buf.Bytes()
}

func (c *captureConn) containedInSingleWrite(needle []byte) bool {
	for _, w := range c.writes {
		if bytes.Contains(w, needle) {
			return true
		}
	}
	return false
}

func captureClientHello(t *testing.T, browser string, fragmentSize, handshakeLen int) *captureConn {
	t.Helper()
	cfg, err := BuildCamouflageConfig(defaultSNI, browser, 200*time.Millisecond)
	require.NoError(t, err)

	cap := &captureConn{}
	mc, err := manet.WrapNetConn(cap)
	require.NoError(t, err)

	s := NewSpoofConn(mc, fragmentSize, handshakeLen, 0, defaultSNI)
	_, _ = clientTLSHandshake(s, cfg)

	require.NotEmpty(t, cap.writes, "no ClientHello was written")
	return cap
}

func TestFragmentation_SNINeverInOneSegment(t *testing.T) {
	sni := []byte(defaultSNI)

	for _, browser := range []string{BrowserChrome, BrowserFirefox, BrowserSafari, BrowserIOS} {
		t.Run(browser, func(t *testing.T) {
			for i := 0; i < 25; i++ {
				cap := captureClientHello(t, browser, DefaultFragmentSize, DefaultHandshakeLen)

				require.Contains(t, string(cap.stream()), defaultSNI,
					"iteration %d: SNI should be present in the reassembled stream", i)
				assert.False(t, cap.containedInSingleWrite(sni),
					"iteration %d: SNI landed intact in one segment — first-segment DPI can match it "+
						"(ClientHello was %d bytes, handshakeLen=%d)",
					i, len(cap.stream()), DefaultHandshakeLen)
			}
		})
	}
}

func TestFragmentation_ClientHelloLeavesInTwoSegments(t *testing.T) {
	for _, browser := range []string{BrowserChrome, BrowserFirefox, BrowserSafari, BrowserIOS} {
		t.Run(browser, func(t *testing.T) {
			for i := 0; i < 10; i++ {
				cap := captureClientHello(t, browser, DefaultFragmentSize, DefaultHandshakeLen)

				require.Len(t, cap.writes, 2,
					"iteration %d: the ClientHello must go out as two segments cut inside "+
						"the SNI; shredding it into many tiny segments is itself a signature",
					i)
				assert.Greater(t, len(cap.writes[0]), DefaultFragmentSize,
					"iteration %d: segments must stay browser-sized", i)
			}
		})
	}
}

func TestFragmentation_DefaultLatencyFitsHolePunchBudget(t *testing.T) {
	cfg, err := BuildCamouflageConfig(defaultSNI, BrowserChrome, defaultHandshakeTimeout)
	require.NoError(t, err)

	a, b := simultaneousOpenPair(t)
	out := make(chan error, 2)
	run := func(c net.Conn, isClient bool) {
		mc, err := manet.WrapNetConn(c)
		if err != nil {
			out <- err
			return
		}
		s := NewSpoofConn(mc, DefaultFragmentSize, DefaultHandshakeLen, DefaultMaxDelay, defaultSNI)
		cc, err := NewCamouflageConn(s, isClient, cfg)
		if cc != nil {
			defer cc.Close()
		}
		out <- err
	}
	start := time.Now()
	go run(a, true)
	go run(b, false)
	for i := 0; i < 2; i++ {
		require.NoError(t, <-out)
	}
	elapsed := time.Since(start)

	t.Logf("camouflage handshake with defaults: %v (loopback, RTT~0)", elapsed)
	assert.Less(t, elapsed, 500*time.Millisecond,
		"handshake must leave room in the 10s hole-punch budget for real RTT")
}
