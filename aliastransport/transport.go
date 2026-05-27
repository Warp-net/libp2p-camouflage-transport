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
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Warp-net/libp2p-camouflage-transport/aliasresolver"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
)

// DialTimeout caps how long a single resolve handshake (open stream to
// relay, send id, read status) may take before being aborted.
var DialTimeout = 30 * time.Second

// Transport is the libp2p transport that dials and listens via
// /warpid/<hex> alias addresses on a relay.
type Transport struct {
	host     host.Host
	upgrader transport.Upgrader
	privKey  crypto.PrivKey
	warpID   string

	mu        sync.Mutex
	listeners map[peer.ID]*aliasedListener // keyed by relay peer
	started   bool
}

var (
	_ transport.Transport = (*Transport)(nil)
)

// New constructs a Transport. The libp2p upgrader and host come from the
// libp2p.Transport dependency-injection graph; privKey and warpID are
// supplied by the caller via NewFactory.
func New(upgrader transport.Upgrader, h host.Host, privKey crypto.PrivKey, warpID string) (*Transport, error) {
	if h == nil {
		return nil, errors.New("aliastransport: host is nil")
	}
	if upgrader == nil {
		return nil, errors.New("aliastransport: upgrader is nil")
	}
	if privKey == nil {
		return nil, errors.New("aliastransport: privKey is nil")
	}
	if warpID == "" {
		return nil, errors.New("aliastransport: warpID is empty")
	}
	t := &Transport{
		host:      h,
		upgrader:  upgrader,
		privKey:   privKey,
		warpID:    warpID,
		listeners: make(map[peer.ID]*aliasedListener),
	}
	t.start()
	return t, nil
}

// start installs the stop-protocol stream handler. Multiple Transport
// instances on the same host would collide; we treat that as
// misconfiguration and overwrite (last writer wins).
func (t *Transport) start() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started {
		return
	}
	t.host.SetStreamHandler(aliasresolver.StopProtocol, t.handleStopStream)
	t.started = true
}

// handleStopStream is invoked when a relay opens an inbound stream for
// a dialer it has resolved to us. We route the stream to the listener
// registered for that relay; streams from unexpected peers are dropped.
func (t *Transport) handleStopStream(s network.Stream) {
	relay := s.Conn().RemotePeer()

	t.mu.Lock()
	l, ok := t.listeners[relay]
	t.mu.Unlock()
	if !ok {
		log.Printf("aliastransport: stop stream from unregistered relay %s", relay)
		_ = s.Reset()
		return
	}
	if !l.deliver(s) {
		_ = s.Reset()
	}
}

// Protocols advertises the warpid multiaddr code so the libp2p swarm
// routes matching multiaddrs to this transport.
func (t *Transport) Protocols() []int { return []int{P_WARPID} }

// Proxy returns true: like p2p-circuit, this transport relays through
// a third party and must be preferred over the inner transport when a
// multiaddr contains /warpid/.
func (t *Transport) Proxy() bool { return true }

// CanDial returns true for any multiaddr containing a /warpid/ component.
func (t *Transport) CanDial(addr ma.Multiaddr) bool {
	_, err := addr.ValueForProtocol(P_WARPID)
	return err == nil
}

// Dial opens a stream to the relay encoded in raddr, asks it to resolve
// the WarpID, and runs the libp2p upgrade (Noise + muxer) over the
// resulting bidirectional pipe. The target peer is authenticated by the
// upgrade, not by the relay.
func (t *Transport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	relayID, warpID, err := splitDialAddr(raddr)
	if err != nil {
		return nil, err
	}

	scope, err := t.host.Network().ResourceManager().OpenConnection(network.DirOutbound, false, raddr)
	if err != nil {
		return nil, err
	}
	if err := scope.SetPeer(p); err != nil {
		scope.Done()
		return nil, err
	}

	conn, err := t.dial(ctx, raddr, relayID, warpID, p)
	if err != nil {
		scope.Done()
		return nil, err
	}

	cc, err := t.upgrader.Upgrade(ctx, t, conn, network.DirOutbound, p, scope)
	if err != nil {
		_ = conn.Close()
		scope.Done()
		return nil, err
	}
	return cc, nil
}

func (t *Transport) dial(ctx context.Context, raddr ma.Multiaddr, relayID peer.ID, warpID string, p peer.ID) (*streamConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()

	s, err := t.host.NewStream(dialCtx, relayID, aliasresolver.ResolveProtocol)
	if err != nil {
		return nil, fmt.Errorf("aliastransport: open resolve stream to relay %s: %w", relayID, err)
	}

	deadline, ok := dialCtx.Deadline()
	if ok {
		_ = s.SetDeadline(deadline)
	}

	if err := aliasresolver.WriteJSON(s, aliasresolver.ResolveRequest{ID: warpID}); err != nil {
		_ = s.Reset()
		return nil, fmt.Errorf("aliastransport: write resolve request: %w", err)
	}

	br := bufio.NewReader(s)
	status, err := aliasresolver.ReadStatus(br)
	if err != nil {
		_ = s.Reset()
		return nil, fmt.Errorf("aliastransport: read resolve status: %w", err)
	}
	if status != "ok" {
		_ = s.Reset()
		return nil, fmt.Errorf("aliastransport: relay refused resolve: %q", status)
	}

	// Clear the handshake deadline before handing the stream off.
	_ = s.SetDeadline(time.Time{})

	local := buildAliasMultiaddr(relayID, t.warpID)
	return newStreamConn(s, br, local, raddr), nil
}

// Listen registers this peer's WarpID on the relay encoded in laddr and
// returns a listener whose advertised address is /p2p/<relayID>/warpid/<id>.
// The listener accepts streams the relay opens back to us in response to
// resolve requests.
func (t *Transport) Listen(laddr ma.Multiaddr) (transport.Listener, error) {
	relayID, warpID, err := splitListenAddr(laddr)
	if err != nil {
		return nil, err
	}
	if warpID != t.warpID {
		return nil, fmt.Errorf("aliastransport: listen warpID %s != configured %s", warpID, t.warpID)
	}

	t.mu.Lock()
	if _, exists := t.listeners[relayID]; exists {
		t.mu.Unlock()
		return nil, fmt.Errorf("aliastransport: already listening via relay %s", relayID)
	}
	l := newAliasedListener(t, relayID, warpID)
	t.listeners[relayID] = l
	t.mu.Unlock()

	if err := t.registerOnRelay(context.Background(), relayID); err != nil {
		t.mu.Lock()
		delete(t.listeners, relayID)
		t.mu.Unlock()
		return nil, err
	}

	return t.upgrader.UpgradeGatedMaListener(t, l), nil
}

// registerOnRelay signs the WarpID with our private key and pushes the
// registration over RegisterProtocol. The relay verifies the signature
// against the connection's RemotePublicKey, so the signed material need
// only bind the alias to our identity.
func (t *Transport) registerOnRelay(ctx context.Context, relayID peer.ID) error {
	dialCtx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()

	s, err := t.host.NewStream(dialCtx, relayID, aliasresolver.RegisterProtocol)
	if err != nil {
		return fmt.Errorf("aliastransport: open register stream to relay %s: %w", relayID, err)
	}
	defer s.Close()

	deadline, ok := dialCtx.Deadline()
	if ok {
		_ = s.SetDeadline(deadline)
	}

	sig, err := t.privKey.Sign([]byte(t.warpID))
	if err != nil {
		_ = s.Reset()
		return fmt.Errorf("aliastransport: sign warpID: %w", err)
	}

	if err := aliasresolver.WriteJSON(s, aliasresolver.RegisterRequest{ID: t.warpID, Sig: sig}); err != nil {
		_ = s.Reset()
		return fmt.Errorf("aliastransport: write register request: %w", err)
	}

	br := bufio.NewReader(s)
	status, err := aliasresolver.ReadStatus(br)
	if err != nil {
		return fmt.Errorf("aliastransport: read register status: %w", err)
	}
	if status != "ok" {
		return fmt.Errorf("aliastransport: relay refused register: %q", status)
	}
	return nil
}

func (t *Transport) removeListener(relayID peer.ID, l *aliasedListener) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur, ok := t.listeners[relayID]; ok && cur == l {
		delete(t.listeners, relayID)
	}
}

// splitDialAddr extracts the relay peer.ID and warpID from a dial
// multiaddr of the form .../p2p/<relay>/warpid/<id>[/p2p/<target>].
func splitDialAddr(a ma.Multiaddr) (peer.ID, string, error) {
	warpComp, _, err := splitOnWarpID(a)
	if err != nil {
		return "", "", err
	}
	prefix, _ := ma.SplitFunc(a, func(c ma.Component) bool {
		return c.Protocol().Code == P_WARPID
	})
	if prefix == nil {
		return "", "", fmt.Errorf("aliastransport: missing relay before /warpid/ in %s", a)
	}
	relayIDStr, err := prefix.ValueForProtocol(ma.P_P2P)
	if err != nil {
		return "", "", fmt.Errorf("aliastransport: no /p2p/<relayID> in %s", a)
	}
	relayID, err := peer.Decode(relayIDStr)
	if err != nil {
		return "", "", fmt.Errorf("aliastransport: invalid relay peer id %q: %w", relayIDStr, err)
	}
	return relayID, warpComp.Value(), nil
}

// splitListenAddr accepts /p2p/<relay>/warpid/<id> (no trailing /p2p/).
func splitListenAddr(a ma.Multiaddr) (peer.ID, string, error) {
	warpComp, tail, err := splitOnWarpID(a)
	if err != nil {
		return "", "", err
	}
	if tail != nil {
		return "", "", fmt.Errorf("aliastransport: listen address must end at /warpid/, got %s", a)
	}
	prefix, _ := ma.SplitFunc(a, func(c ma.Component) bool {
		return c.Protocol().Code == P_WARPID
	})
	if prefix == nil {
		return "", "", fmt.Errorf("aliastransport: missing relay before /warpid/ in %s", a)
	}
	relayIDStr, err := prefix.ValueForProtocol(ma.P_P2P)
	if err != nil {
		return "", "", fmt.Errorf("aliastransport: no /p2p/<relayID> in %s", a)
	}
	relayID, err := peer.Decode(relayIDStr)
	if err != nil {
		return "", "", fmt.Errorf("aliastransport: invalid relay peer id %q: %w", relayIDStr, err)
	}
	return relayID, warpComp.Value(), nil
}

// splitOnWarpID returns (warpComponent, tailAfterWarp, error). tail is
// nil when there is nothing after /warpid/<id>.
func splitOnWarpID(a ma.Multiaddr) (*ma.Component, ma.Multiaddr, error) {
	var warpComp *ma.Component
	var tail ma.Multiaddr
	var sawWarp bool
	ma.ForEach(a, func(c ma.Component) bool {
		if sawWarp {
			if tail == nil {
				tail = c.Multiaddr()
			} else {
				tail = ma.Join(tail, c.Multiaddr())
			}
			return true
		}
		if c.Protocol().Code == P_WARPID {
			cc := c
			warpComp = &cc
			sawWarp = true
		}
		return true
	})
	if warpComp == nil {
		return nil, nil, fmt.Errorf("aliastransport: address %s has no /warpid/ component", a)
	}
	return warpComp, tail, nil
}

// buildAliasMultiaddr returns /p2p/<relayID>/warpid/<warpID>.
func buildAliasMultiaddr(relayID peer.ID, warpID string) ma.Multiaddr {
	relay, err := ma.NewComponent("p2p", relayID.String())
	if err != nil {
		return nil
	}
	wid, err := ma.NewComponent(WarpIDName, warpID)
	if err != nil {
		return nil
	}
	return ma.Join(relay.Multiaddr(), wid.Multiaddr())
}
