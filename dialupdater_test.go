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
	"testing"
	"time"

	tpt "github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDialUpdater_ReportsHandshakeProgressed(t *testing.T) {
	uA, _ := newTestUpgrader(t)
	uB, idB := newTestUpgrader(t)
	dialer := newTestTransport(t, uA)
	listenerTpt := newTestTransport(t, uB)

	laddr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	require.NoError(t, err)
	ln, err := listenerTpt.Listen(laddr)
	require.NoError(t, err)
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			close(accepted)
			<-time.After(time.Second)
			c.Close()
			return
		}
		close(accepted)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	updCh := make(chan tpt.DialUpdate, 4)
	conn, err := dialer.DialWithUpdates(ctx, ln.Multiaddr(), idB, updCh)
	require.NoError(t, err)
	defer conn.Close()

	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("listener never accepted")
	}

	var got []tpt.DialUpdateKind
	for {
		select {
		case u := <-updCh:
			got = append(got, u.Kind)
			continue
		default:
		}
		break
	}
	assert.Contains(t, got, tpt.UpdateKindHandshakeProgressed,
		"transport must report the TCP handshake, got %v", got)
}

func TestDialUpdater_NilChannelIsFine(t *testing.T) {
	uA, _ := newTestUpgrader(t)
	uB, idB := newTestUpgrader(t)
	dialer := newTestTransport(t, uA)
	listenerTpt := newTestTransport(t, uB)

	laddr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	require.NoError(t, err)
	ln, err := listenerTpt.Listen(laddr)
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		if c, err := ln.Accept(); err == nil {
			<-time.After(time.Second)
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := dialer.Dial(ctx, ln.Multiaddr(), idB)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}

func TestDialUpdater_SlowConsumerDoesNotBlock(t *testing.T) {
	uA, _ := newTestUpgrader(t)
	uB, idB := newTestUpgrader(t)
	dialer := newTestTransport(t, uA)
	listenerTpt := newTestTransport(t, uB)

	laddr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/0")
	require.NoError(t, err)
	ln, err := listenerTpt.Listen(laddr)
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		if c, err := ln.Accept(); err == nil {
			<-time.After(time.Second)
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	updCh := make(chan tpt.DialUpdate)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := dialer.DialWithUpdates(ctx, ln.Multiaddr(), idB, updCh)
		if err == nil {
			conn.Close()
		}
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("dial blocked on the update channel")
	}
}
