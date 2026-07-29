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
	"context"
	"net"
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestAcceptHeadOfLineBlocking(t *testing.T) {
	uA, _ := newTestUpgrader(t)
	uB, idB := newTestUpgrader(t)
	dialer := newTestTransport(t, uA)
	listenerTpt := newTestTransport(t, uB)

	laddr, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	ln, err := listenerTpt.Listen(laddr)
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { <-time.After(2 * time.Second); c.Close() }()
		}
	}()

	host, err := ln.Multiaddr().ValueForProtocol(ma.P_IP4)
	require.NoError(t, err)
	port, err := ln.Multiaddr().ValueForProtocol(ma.P_TCP)
	require.NoError(t, err)
	addr := net.JoinHostPort(host, port)

	tarpit, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer tarpit.Close()
	t.Logf("tarpit connected from %s, sending nothing", tarpit.LocalAddr())

	time.Sleep(300 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dialer.Dial(ctx, ln.Multiaddr(), idB)
	elapsed := time.Since(start)
	if conn != nil {
		conn.Close()
	}
	t.Logf("legitimate dial took %v (err=%v)", elapsed, err)

	require.NoError(t, err, "a silent peer must not break inbound connectivity")
	require.Less(t, elapsed, 2*time.Second,
		"legitimate dial was stalled by a single silent peer: the TLS handshake "+
			"runs inside Accept(), which the upgrader calls serially")
}
