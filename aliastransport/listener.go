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
	"net"
	"sync"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// aliasedListener implements transport.GatedMaListener. The advertised
// multiaddr is /p2p/<relayID>/warpid/<warpID>; no IP ever leaves this
// peer, which is the whole point of the transport.
type aliasedListener struct {
	t       *Transport
	relayID peer.ID
	warpID  string
	addr    ma.Multiaddr

	incoming chan network.Stream

	closeOnce sync.Once
	closed    chan struct{}
}

var _ transport.GatedMaListener = (*aliasedListener)(nil)

func newAliasedListener(t *Transport, relayID peer.ID, warpID string) *aliasedListener {
	return &aliasedListener{
		t:        t,
		relayID:  relayID,
		warpID:   warpID,
		addr:     buildAliasMultiaddr(relayID, warpID),
		incoming: make(chan network.Stream, 16),
		closed:   make(chan struct{}),
	}
}

// deliver hands an inbound stream to a pending Accept. Returns false if
// the listener has been closed or the queue is saturated, in which case
// the caller should reset the stream.
func (l *aliasedListener) deliver(s network.Stream) bool {
	select {
	case <-l.closed:
		return false
	default:
	}
	select {
	case l.incoming <- s:
		return true
	case <-l.closed:
		return false
	}
}

func (l *aliasedListener) Accept() (manet.Conn, network.ConnManagementScope, error) {
	for {
		select {
		case s := <-l.incoming:
			scope, err := l.t.host.Network().ResourceManager().OpenConnection(network.DirInbound, false, l.addr)
			if err != nil {
				_ = s.Reset()
				continue
			}
			conn := newStreamConn(s, nil, l.addr, l.addr)
			return conn, scope, nil
		case <-l.closed:
			return nil, nil, transport.ErrListenerClosed
		}
	}
}

func (l *aliasedListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		l.t.removeListener(l.relayID, l)
		// Drain any pending streams so they don't leak.
		for {
			select {
			case s := <-l.incoming:
				_ = s.Reset()
			default:
				return
			}
		}
	})
	return nil
}

func (l *aliasedListener) Multiaddr() ma.Multiaddr { return l.addr }

func (l *aliasedListener) Addr() net.Addr {
	return aliasNetAddr{label: l.addr.String()}
}
