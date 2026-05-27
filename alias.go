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

// alias.go: IP-hiding mode for CamouflageTransport. When a node has been
// configured with WithWarpID(...), it can also listen on and dial
//
//	/p2p/<relayID>/warpid/<hex>[/p2p/<peerID>]
//
// addresses. Identify, peerstore and DHT then see only the alias — never
// an IP. The underlying TCP+TLS leg to the relay still goes through the
// DPI-evasion path implemented in camouflage.go.

package camouflage

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Warp-net/libp2p-camouflage-transport/aliasresolver"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
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

// AliasDialTimeout caps how long a single resolve handshake (open stream
// to relay, send id, read status) may take before being aborted.
var AliasDialTimeout = 30 * time.Second

var errInvalidWarpID = errors.New("warpid: invalid value")

// init registers the /warpid/ multiaddr protocol. It runs on package
// import, which makes the protocol available everywhere the transport is
// linked in. Calling AddProtocol twice with the same code returns an
// error; we swallow it because identical re-registration is harmless.
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

// hasWarpID reports whether the multiaddr contains a /warpid/ component.
func hasWarpID(a ma.Multiaddr) bool {
	_, err := a.ValueForProtocol(P_WARPID)
	return err == nil
}

// dialAlias performs the relay-mediated resolve and returns an upgraded
// libp2p connection to the target peer. Authentication of `p` is done
// by the libp2p upgrader inside the relayed stream; the relay sees
// ciphertext only.
func (t *CamouflageTransport) dialAlias(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	relayID, warpID, err := splitAliasDialAddr(raddr)
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

	conn, err := t.openResolveStream(ctx, raddr, relayID, warpID)
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

func (t *CamouflageTransport) openResolveStream(ctx context.Context, raddr ma.Multiaddr, relayID peer.ID, warpID string) (*aliasStreamConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, AliasDialTimeout)
	defer cancel()

	s, err := t.host.NewStream(dialCtx, relayID, aliasresolver.ResolveProtocol)
	if err != nil {
		return nil, fmt.Errorf("camouflage/alias: open resolve stream to relay %s: %w", relayID, err)
	}

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = s.SetDeadline(deadline)
	}

	if err := aliasresolver.WriteResolveFrame(s, warpID); err != nil {
		_ = s.Reset()
		return nil, fmt.Errorf("camouflage/alias: write resolve request: %w", err)
	}

	ok, err := aliasresolver.ReadStatus(s)
	if err != nil {
		_ = s.Reset()
		return nil, fmt.Errorf("camouflage/alias: read resolve status: %w", err)
	}
	if !ok {
		_ = s.Reset()
		return nil, fmt.Errorf("camouflage/alias: relay refused resolve for %s", warpID)
	}

	// Clear the handshake deadline before handing the stream off to
	// the upgrader, which will run its own Noise handshake.
	_ = s.SetDeadline(time.Time{})

	local := buildAliasMultiaddr(relayID, t.warpID)
	return newAliasStreamConn(s, local, raddr), nil
}

// listenAlias registers this peer's WarpID on the relay encoded in laddr
// and returns a listener whose advertised address is only the alias.
func (t *CamouflageTransport) listenAlias(laddr ma.Multiaddr) (transport.Listener, error) {
	if t.warpID == "" {
		return nil, errors.New("camouflage/alias: cannot listen — no WarpID configured (use WithWarpID)")
	}
	if t.privKey == nil {
		return nil, errors.New("camouflage/alias: cannot listen — host private key unavailable")
	}

	relayID, warpID, err := splitAliasListenAddr(laddr)
	if err != nil {
		return nil, err
	}
	if warpID != t.warpID {
		return nil, fmt.Errorf("camouflage/alias: listen warpID %s != configured %s", warpID, t.warpID)
	}

	t.aliasMu.Lock()
	if t.aliasListener != nil {
		existing := t.aliasListener.relayID
		t.aliasMu.Unlock()
		return nil, fmt.Errorf("camouflage/alias: already listening via relay %s", existing)
	}
	l := newAliasedListener(t, relayID, warpID)
	t.aliasListener = l
	t.aliasMu.Unlock()

	if err := t.registerOnRelay(context.Background(), relayID); err != nil {
		t.aliasMu.Lock()
		if t.aliasListener == l {
			t.aliasListener = nil
		}
		t.aliasMu.Unlock()
		return nil, err
	}

	return t.upgrader.UpgradeGatedMaListener(t, l), nil
}

// registerOnRelay signs the WarpID with the host's private key and sends
// it on RegisterProtocol. The relay verifies the signature against the
// connection's RemotePublicKey, so the signed material need only bind the
// alias to our identity.
func (t *CamouflageTransport) registerOnRelay(ctx context.Context, relayID peer.ID) error {
	dialCtx, cancel := context.WithTimeout(ctx, AliasDialTimeout)
	defer cancel()

	s, err := t.host.NewStream(dialCtx, relayID, aliasresolver.RegisterProtocol)
	if err != nil {
		return fmt.Errorf("camouflage/alias: open register stream to relay %s: %w", relayID, err)
	}
	defer s.Close()

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = s.SetDeadline(deadline)
	}

	sig, err := t.privKey.Sign([]byte(t.warpID))
	if err != nil {
		_ = s.Reset()
		return fmt.Errorf("camouflage/alias: sign warpID: %w", err)
	}

	if err := aliasresolver.WriteRegisterFrame(s, t.warpID, sig); err != nil {
		_ = s.Reset()
		return fmt.Errorf("camouflage/alias: write register request: %w", err)
	}

	ok, err := aliasresolver.ReadStatus(s)
	if err != nil {
		return fmt.Errorf("camouflage/alias: read register status: %w", err)
	}
	if !ok {
		return fmt.Errorf("camouflage/alias: relay refused register")
	}
	return nil
}

// handleStopStream is invoked when a relay opens an inbound stream for a
// dialer it has resolved to us. The sender must be the relay our active
// listener registered with; streams from any other peer are dropped.
func (t *CamouflageTransport) handleStopStream(s network.Stream) {
	remote := s.Conn().RemotePeer()

	t.aliasMu.Lock()
	l := t.aliasListener
	t.aliasMu.Unlock()
	if l == nil || l.relayID != remote {
		log.Printf("camouflage/alias: stop stream from unexpected peer %s", remote)
		_ = s.Reset()
		return
	}
	if !l.deliver(s) {
		_ = s.Reset()
	}
}

func (t *CamouflageTransport) clearAliasListener(l *aliasedListener) {
	t.aliasMu.Lock()
	defer t.aliasMu.Unlock()
	if t.aliasListener == l {
		t.aliasListener = nil
	}
}

// ---------- multiaddr helpers ----------

// splitAliasDialAddr extracts the relay peer.ID and warpID from a dial
// multiaddr of the form .../p2p/<relay>/warpid/<id>[/p2p/<target>].
func splitAliasDialAddr(a ma.Multiaddr) (peer.ID, string, error) {
	warpComp, _, err := splitOnWarpID(a)
	if err != nil {
		return "", "", err
	}
	prefix, _ := ma.SplitFunc(a, func(c ma.Component) bool {
		return c.Protocol().Code == P_WARPID
	})
	if prefix == nil {
		return "", "", fmt.Errorf("camouflage/alias: missing relay before /warpid/ in %s", a)
	}
	relayIDStr, err := prefix.ValueForProtocol(ma.P_P2P)
	if err != nil {
		return "", "", fmt.Errorf("camouflage/alias: no /p2p/<relayID> in %s", a)
	}
	relayID, err := peer.Decode(relayIDStr)
	if err != nil {
		return "", "", fmt.Errorf("camouflage/alias: invalid relay peer id %q: %w", relayIDStr, err)
	}
	return relayID, warpComp.Value(), nil
}

// splitAliasListenAddr accepts /p2p/<relay>/warpid/<id> (no trailing /p2p/).
func splitAliasListenAddr(a ma.Multiaddr) (peer.ID, string, error) {
	warpComp, tail, err := splitOnWarpID(a)
	if err != nil {
		return "", "", err
	}
	if tail != nil {
		return "", "", fmt.Errorf("camouflage/alias: listen address must end at /warpid/, got %s", a)
	}
	prefix, _ := ma.SplitFunc(a, func(c ma.Component) bool {
		return c.Protocol().Code == P_WARPID
	})
	if prefix == nil {
		return "", "", fmt.Errorf("camouflage/alias: missing relay before /warpid/ in %s", a)
	}
	relayIDStr, err := prefix.ValueForProtocol(ma.P_P2P)
	if err != nil {
		return "", "", fmt.Errorf("camouflage/alias: no /p2p/<relayID> in %s", a)
	}
	relayID, err := peer.Decode(relayIDStr)
	if err != nil {
		return "", "", fmt.Errorf("camouflage/alias: invalid relay peer id %q: %w", relayIDStr, err)
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
		return nil, nil, fmt.Errorf("camouflage/alias: address %s has no /warpid/ component", a)
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

// ---------- stream conn ----------

// aliasStreamConn wraps a libp2p network.Stream as a manet.Conn so the
// libp2p upgrader can run Noise + a stream muxer over it. The binary
// register/resolve framing has a deterministic length, so we read it
// straight off the stream — no bufio.Reader, no leftover bytes to
// shepherd into the data-piping phase.
type aliasStreamConn struct {
	stream network.Stream

	local  ma.Multiaddr
	remote ma.Multiaddr
}

var _ manet.Conn = (*aliasStreamConn)(nil)

func newAliasStreamConn(s network.Stream, local, remote ma.Multiaddr) *aliasStreamConn {
	return &aliasStreamConn{
		stream: s,
		local:  local,
		remote: remote,
	}
}

func (c *aliasStreamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *aliasStreamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *aliasStreamConn) Close() error                { return c.stream.Close() }

func (c *aliasStreamConn) LocalAddr() net.Addr  { return aliasNetAddr{label: c.local.String()} }
func (c *aliasStreamConn) RemoteAddr() net.Addr { return aliasNetAddr{label: c.remote.String()} }

func (c *aliasStreamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *aliasStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *aliasStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

func (c *aliasStreamConn) LocalMultiaddr() ma.Multiaddr  { return c.local }
func (c *aliasStreamConn) RemoteMultiaddr() ma.Multiaddr { return c.remote }

type aliasNetAddr struct {
	label string
}

func (a aliasNetAddr) Network() string { return "libp2p-warpid" }
func (a aliasNetAddr) String() string  { return a.label }

// ---------- listener ----------

// aliasedListener implements transport.GatedMaListener. The advertised
// multiaddr is /p2p/<relayID>/warpid/<warpID>; no IP ever leaves this
// peer, which is the whole point of the alias mode.
type aliasedListener struct {
	t       *CamouflageTransport
	relayID peer.ID
	warpID  string
	addr    ma.Multiaddr

	incoming chan network.Stream

	closeOnce sync.Once
	closed    chan struct{}
}

var _ transport.GatedMaListener = (*aliasedListener)(nil)

func newAliasedListener(t *CamouflageTransport, relayID peer.ID, warpID string) *aliasedListener {
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
// the listener has been closed.
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
			conn := newAliasStreamConn(s, l.addr, l.addr)
			return conn, scope, nil
		case <-l.closed:
			return nil, nil, transport.ErrListenerClosed
		}
	}
}

func (l *aliasedListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		l.t.clearAliasListener(l)
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
