// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package camouflage_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	camouflage "github.com/Warp-net/libp2p-camouflage-transport"
	"github.com/Warp-net/libp2p-camouflage-transport/aliasresolver"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/core/transport"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

const echoProtoAlias protocol.ID = "/test/alias-echo/0.0.0"

func freshWarpID(t *testing.T) string {
	t.Helper()
	b := make([]byte, camouflage.WarpIDByteLen)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

// makeThinHost mirrors the warpdroid thin-client setup: no listen addrs,
// only the camouflage TCP transport, circuit-v2 relay client enabled,
// yamux muxer, identify-discovery disabled. Alias mode is wired up in
// dial-only mode (empty WarpID) — the thin node only resolves other
// peers' aliases, it never registers one of its own.
func makeThinHost(t *testing.T) host.Host {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	ya := yamux.DefaultTransport
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.NoTransports,
		libp2p.NoListenAddrs,
		libp2p.EnableRelay(),
		libp2p.DisableIdentifyAddressDiscovery(),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(camouflage.NewCamouflageTransport),
		libp2p.Muxer(yamux.ID, ya),
		libp2p.UserAgent("warpdroid-test"),
	)
	require.NoError(t, err)
	require.NoError(t, camouflage.EnableAlias(h, ""))
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// TestThinNodeDialsAliasListener spins up a relay, a fat alias-listener,
// and a warpdroid-style thin client. The thin client never listens and
// never registers a WarpID; it just dials the listener through the
// relay using a /warpid/ multiaddr and exchanges one echo message.
func TestThinNodeDialsAliasListener(t *testing.T) {
	warpID := freshWarpID(t)

	relayH, resolver := makeRelay(t)
	listenerH := makeHost(t, warpID)
	thinH := makeThinHost(t)

	listenerH.SetStreamHandler(echoProtoAlias, func(s network.Stream) {
		defer s.Close()
		_, _ = io.Copy(s, s)
	})

	// Listener connects to the relay; the alias auto-finder picks up
	// /warpnet/alias-register/0.0.0 from identify and Listens on its
	// own — no manual Listen call required.
	connect(t, listenerH, relayH)
	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 5*time.Second, 20*time.Millisecond)

	// Thin node connects to the relay over the plain TCP+camouflage
	// leg — same way warpdroid reaches a bootstrap.
	connect(t, thinH, relayH)

	// Sanity: thin node really has no public listen addresses.
	require.Empty(t, thinH.Addrs(), "thin node must not advertise any addrs")

	// Now dial the listener purely by alias multiaddr.
	target, err := ma.NewMultiaddr(
		"/p2p/" + relayH.ID().String() +
			"/warpid/" + warpID +
			"/p2p/" + listenerH.ID().String(),
	)
	require.NoError(t, err)
	thinH.Peerstore().AddAddr(listenerH.ID(), target, peerstore.TempAddrTTL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := thinH.NewStream(ctx, listenerH.ID(), echoProtoAlias)
	require.NoError(t, err)
	defer s.Close()

	payload := []byte("from-thin-node")
	_, err = s.Write(payload)
	require.NoError(t, err)
	require.NoError(t, s.CloseWrite())

	got, err := io.ReadAll(s)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

// TestThinNodeCannotListenAlias asserts that a dial-only thin host
// rejects attempts to Listen on a /warpid/ multiaddr — the listen path
// needs a non-empty WarpID, which EnableAlias("") deliberately does
// not provide.
func TestThinNodeCannotListenAlias(t *testing.T) {
	relayH, _ := makeRelay(t)
	thinH := makeThinHost(t)

	connect(t, thinH, relayH)

	listenAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + freshWarpID(t))
	require.NoError(t, err)
	err = thinH.Network().Listen(listenAddr)
	require.Error(t, err, "thin node must not be able to register an alias")
}

// makeHost spins up a libp2p host configured with CamouflageTransport
// and turns on alias mode via the post-host EnableAlias call. An empty
// warpID still enables the layer in dial-only mode.
func makeHost(t *testing.T, warpID string) host.Host {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(camouflage.NewCamouflageTransport),
	)
	require.NoError(t, err)
	require.NoError(t, camouflage.EnableAlias(h, warpID))
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// makeRelay wires CamouflageTransport on the relay too, so listeners
// and dialers can reach it via the DPI-resistant TLS leg. The relay
// itself never registers an alias — it just serves the resolver via
// EnableAliasService, the alias counterpart of libp2p.EnableRelayService.
func makeRelay(t *testing.T) (host.Host, *aliasresolver.Resolver) {
	t.Helper()
	h := makeHost(t, "")
	r, err := camouflage.EnableAliasService(h)
	require.NoError(t, err)
	t.Cleanup(r.Stop)
	return h, r
}

func connect(t *testing.T, src, dst host.Host) {
	t.Helper()
	src.Peerstore().AddAddrs(dst.ID(), dst.Addrs(), peerstore.PermanentAddrTTL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, src.Connect(ctx, peer.AddrInfo{ID: dst.ID(), Addrs: dst.Addrs()}))
}

// TestResolverEvictsOnDisconnect verifies that when a registered peer
// fully disconnects from the relay, its WarpID is removed from the
// resolver table. Without this the table would grow unbounded on a
// public relay as peers churn.
func TestResolverEvictsOnDisconnect(t *testing.T) {
	warpID := freshWarpID(t)

	relayH, resolver := makeRelay(t)
	listenerH := makeHost(t, warpID)

	connect(t, listenerH, relayH)

	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 5*time.Second, 20*time.Millisecond, "expected auto-listen registration to land")

	// Close the listener-side host so the relay observes a disconnect.
	require.NoError(t, listenerH.Close())

	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return !ok
	}, 5*time.Second, 50*time.Millisecond, "registration should be evicted after disconnect")
}

// TestPlainTCPDialUnaffectedByAliasMode verifies that hosts wired with
// WithWarpID still dial each other directly over /ip4/.../tcp/... with
// the normal DPI-camouflaged TCP path; the alias layer must not get in
// the way of plain multiaddrs.
func TestPlainTCPDialUnaffectedByAliasMode(t *testing.T) {
	// Both hosts opt into alias mode but never talk through a relay.
	listenerH := makeHost(t, freshWarpID(t))
	dialerH := makeHost(t, freshWarpID(t))

	listenerH.SetStreamHandler(echoProtoAlias, func(s network.Stream) {
		defer s.Close()
		_, _ = io.Copy(s, s)
	})

	// Dial via the listener's real /ip4/.../tcp/... address.
	dialerH.Peerstore().AddAddrs(listenerH.ID(), listenerH.Addrs(), peerstore.PermanentAddrTTL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := dialerH.NewStream(ctx, listenerH.ID(), echoProtoAlias)
	require.NoError(t, err)
	defer s.Close()

	// Sanity: the stream really went through the camouflage transport,
	// not a circuit-relay path. The connection's local/remote multiaddrs
	// must carry /tcp/ and no /warpid/.
	conn := s.Conn()
	require.False(t, strings.Contains(conn.RemoteMultiaddr().String(), "/warpid/"),
		"plain-TCP dial must not pick up a /warpid/ leg, got %s", conn.RemoteMultiaddr())
	_, err = conn.RemoteMultiaddr().ValueForProtocol(ma.P_TCP)
	require.NoError(t, err, "expected /tcp/ in RemoteMultiaddr %s", conn.RemoteMultiaddr())

	payload := []byte("hello over plain tcp")
	_, err = s.Write(payload)
	require.NoError(t, err)
	require.NoError(t, s.CloseWrite())

	got, err := io.ReadAll(s)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

// ---------- multiaddr / parser unit tests ----------

func TestWarpIDProtocolRegistered(t *testing.T) {
	p := ma.ProtocolWithCode(camouflage.P_WARPID)
	require.Equal(t, camouflage.WarpIDName, p.Name)
	require.Equal(t, camouflage.P_WARPID, p.Code)
}

func TestWarpIDRoundtrip(t *testing.T) {
	id := freshWarpID(t)
	addr, err := ma.NewMultiaddr("/warpid/" + id)
	require.NoError(t, err)

	v, err := addr.ValueForProtocol(camouflage.P_WARPID)
	require.NoError(t, err)
	require.Equal(t, id, v)

	b := addr.Bytes()
	addr2, err := ma.NewMultiaddrBytes(b)
	require.NoError(t, err)
	require.Equal(t, addr.String(), addr2.String())
}

func TestWarpIDRejectsBadLength(t *testing.T) {
	_, err := ma.NewMultiaddr("/warpid/" + strings.Repeat("ab", 10))
	require.Error(t, err)
}

func TestWarpIDRejectsNonHex(t *testing.T) {
	_, err := ma.NewMultiaddr("/warpid/" + strings.Repeat("zz", camouflage.WarpIDByteLen))
	require.Error(t, err)
}

// ---------- end-to-end tests ----------

func TestAliasRoundtrip(t *testing.T) {
	warpID := freshWarpID(t)

	relayH, resolver := makeRelay(t)
	listenerH := makeHost(t, warpID)
	dialerH := makeHost(t, "")

	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	listenerH.SetStreamHandler(echoProtoAlias, func(s network.Stream) {
		defer s.Close()
		_, _ = io.Copy(s, s)
	})

	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 5*time.Second, 20*time.Millisecond)

	target, err := ma.NewMultiaddr(
		"/p2p/" + relayH.ID().String() +
			"/warpid/" + warpID +
			"/p2p/" + listenerH.ID().String(),
	)
	require.NoError(t, err)
	dialerH.Peerstore().AddAddr(listenerH.ID(), target, peerstore.PermanentAddrTTL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := dialerH.NewStream(ctx, listenerH.ID(), echoProtoAlias)
	require.NoError(t, err)
	defer s.Close()

	payload := []byte("hello via warpid")
	_, err = s.Write(payload)
	require.NoError(t, err)
	require.NoError(t, s.CloseWrite())

	buf, err := io.ReadAll(s)
	require.NoError(t, err)
	require.Equal(t, payload, buf)
}

func TestRegisterConflictRejected(t *testing.T) {
	warpID := freshWarpID(t)

	relayH, resolver := makeRelay(t)
	first := makeHost(t, warpID)
	second := makeHost(t, warpID)

	// first registers via auto-finder.
	connect(t, first, relayH)
	require.Eventually(t, func() bool {
		e, ok := resolver.Lookup(warpID)
		return ok && e.Peer == first.ID()
	}, 5*time.Second, 20*time.Millisecond)

	// second's auto-finder will also try to register and be rejected
	// (different owning key). require.Never polls for the duration we
	// allow auto-finder to run and asserts the slot keeps belonging to
	// first — no fixed Sleep, no flakiness across slow CI boxes.
	connect(t, second, relayH)
	require.Never(t, func() bool {
		e, ok := resolver.Lookup(warpID)
		return !ok || e.Peer != first.ID()
	}, 2*time.Second, 50*time.Millisecond, "first owner must continue to hold the slot")

	entry, ok := resolver.Lookup(warpID)
	require.True(t, ok)
	require.Equal(t, first.ID(), entry.Peer)
}

func TestAliasManyConcurrentDials(t *testing.T) {
	warpID := freshWarpID(t)

	relayH, resolver := makeRelay(t)
	listenerH := makeHost(t, warpID)
	dialerH := makeHost(t, "")

	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	listenerH.SetStreamHandler(echoProtoAlias, func(s network.Stream) {
		defer s.Close()
		_, _ = io.Copy(s, s)
	})

	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 5*time.Second, 20*time.Millisecond)

	target, err := ma.NewMultiaddr(
		"/p2p/" + relayH.ID().String() + "/warpid/" + warpID + "/p2p/" + listenerH.ID().String(),
	)
	require.NoError(t, err)
	dialerH.Peerstore().AddAddr(listenerH.ID(), target, peerstore.PermanentAddrTTL)

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			s, err := dialerH.NewStream(ctx, listenerH.ID(), echoProtoAlias)
			if err != nil {
				errs[i] = err
				return
			}
			defer s.Close()
			msg := []byte(fmt.Sprintf("ping-%d", i))
			if _, err := s.Write(msg); err != nil {
				errs[i] = err
				return
			}
			if err := s.CloseWrite(); err != nil {
				errs[i] = err
				return
			}
			got, err := io.ReadAll(s)
			if err != nil {
				errs[i] = err
				return
			}
			if string(got) != string(msg) {
				errs[i] = fmt.Errorf("got %q, want %q", got, msg)
			}
		}()
	}
	wg.Wait()
	for i, e := range errs {
		require.NoErrorf(t, e, "dial %d failed", i)
	}
}

func TestAliasLargePayload(t *testing.T) {
	warpID := freshWarpID(t)

	relayH, resolver := makeRelay(t)
	listenerH := makeHost(t, warpID)
	dialerH := makeHost(t, "")

	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	listenerH.SetStreamHandler(echoProtoAlias, func(s network.Stream) {
		defer s.Close()
		_, _ = io.Copy(s, s)
	})

	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 5*time.Second, 20*time.Millisecond)

	target, err := ma.NewMultiaddr(
		"/p2p/" + relayH.ID().String() + "/warpid/" + warpID + "/p2p/" + listenerH.ID().String(),
	)
	require.NoError(t, err)
	dialerH.Peerstore().AddAddr(listenerH.ID(), target, peerstore.PermanentAddrTTL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := dialerH.NewStream(ctx, listenerH.ID(), echoProtoAlias)
	require.NoError(t, err)
	defer s.Close()

	payload := make([]byte, 512*1024)
	_, err = rand.Read(payload)
	require.NoError(t, err)

	var werr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, werr = s.Write(payload)
		_ = s.CloseWrite()
	}()

	got := make([]byte, len(payload))
	_, err = io.ReadFull(s, got)
	require.NoError(t, err)
	<-done
	require.NoError(t, werr)
	require.Equal(t, payload, got)
}

func TestRegisterSameOwnerIdempotent(t *testing.T) {
	warpID := freshWarpID(t)
	relayH, resolver := makeRelay(t)
	listenerH := makeHost(t, warpID)

	connect(t, listenerH, relayH)

	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 5*time.Second, 20*time.Millisecond)

	entry1, _ := resolver.Lookup(warpID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	priv := listenerH.Peerstore().PrivKey(listenerH.ID())
	require.NotNil(t, priv)
	idBytes, err := hex.DecodeString(warpID)
	require.NoError(t, err)
	sig, err := priv.Sign(idBytes)
	require.NoError(t, err)

	rs, err := listenerH.NewStream(ctx, relayH.ID(), aliasresolver.RegisterProtocol)
	require.NoError(t, err)
	require.NoError(t, aliasresolver.WriteRegisterFrame(rs, warpID, sig))
	ok, err := aliasresolver.ReadStatus(rs)
	require.NoError(t, err)
	require.True(t, ok)
	_ = rs.Close()

	entry2, ok := resolver.Lookup(warpID)
	require.True(t, ok)
	require.Equal(t, entry1.Peer, entry2.Peer)
}

func TestDialUnknownWarpIDFails(t *testing.T) {
	known := freshWarpID(t)
	unknown := freshWarpID(t)

	relayH, _ := makeRelay(t)
	listenerH := makeHost(t, known)
	dialerH := makeHost(t, "")

	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	// The listener will auto-Listen via the relay; we don't care if
	// it has completed, the dial target is an UNREGISTERED WarpID.
	target, err := ma.NewMultiaddr(
		"/p2p/" + relayH.ID().String() + "/warpid/" + unknown + "/p2p/" + listenerH.ID().String(),
	)
	require.NoError(t, err)
	dialerH.Peerstore().AddAddr(listenerH.ID(), target, peerstore.TempAddrTTL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = dialerH.NewStream(ctx, listenerH.ID(), echoProtoAlias)
	require.Error(t, err)
}

func TestDialAfterListenerCloseFails(t *testing.T) {
	warpID := freshWarpID(t)

	relayH, resolver := makeRelay(t)
	listenerH := makeHost(t, warpID)
	dialerH := makeHost(t, "")

	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	listenerH.SetStreamHandler(echoProtoAlias, func(s network.Stream) {
		defer s.Close()
		_, _ = io.Copy(s, s)
	})

	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 5*time.Second, 20*time.Millisecond)

	require.NoError(t, listenerH.Close())

	target, err := ma.NewMultiaddr(
		"/p2p/" + relayH.ID().String() + "/warpid/" + warpID + "/p2p/" + listenerH.ID().String(),
	)
	require.NoError(t, err)
	dialerH.Peerstore().AddAddr(listenerH.ID(), target, peerstore.TempAddrTTL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = dialerH.NewStream(ctx, listenerH.ID(), echoProtoAlias)
	require.Error(t, err)
	require.True(t, err != nil && !errors.Is(err, context.Canceled))
}

func TestListenWithoutWarpIDFails(t *testing.T) {
	relayH, _ := makeRelay(t)
	dialerOnly := makeHost(t, "") // no WarpID configured

	connect(t, dialerOnly, relayH)

	listenAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + freshWarpID(t))
	require.NoError(t, err)
	err = dialerOnly.Network().Listen(listenAddr)
	require.Error(t, err, "Listen must reject a /warpid/ address when no WarpID is configured")
}

// TestSplitAliasDialAddrRejectsGarbageTail verifies that a /warpid/
// followed by anything other than nothing or a single /p2p/<id> is
// rejected — otherwise CanDial would let the swarm pick this transport
// for malformed addrs.
func TestSplitAliasDialAddrRejectsGarbageTail(t *testing.T) {
	relayH, _ := makeRelay(t)
	dialerH := makeHost(t, "")
	connect(t, dialerH, relayH)

	tn, ok := dialerH.Network().(transport.TransportNetwork)
	require.True(t, ok)

	bad, err := ma.NewMultiaddr(
		"/p2p/" + relayH.ID().String() + "/warpid/" + freshWarpID(t) + "/tcp/4001",
	)
	require.NoError(t, err)
	require.Nil(t, tn.(interface {
		TransportForDialing(ma.Multiaddr) transport.Transport
	}).TransportForDialing(bad), "alias addr with /tcp/ tail must not dial")
}

// TestCanDialStructural exercises the structural validation in CanDial.
// A bare /warpid/<id> without a preceding /p2p/<relayID> has no valid
// dial path, so the swarm must not select us for it — verified through
// TransportForDialing, which returns a nil transport when nothing can
// handle the address.
func TestCanDialStructural(t *testing.T) {
	relayH, _ := makeRelay(t)
	dialerH := makeHost(t, "")
	connect(t, dialerH, relayH)

	tn, ok := dialerH.Network().(transport.TransportNetwork)
	require.True(t, ok, "swarm must implement transport.TransportNetwork")

	good, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + freshWarpID(t))
	require.NoError(t, err)
	require.NotNil(t, tn.(interface {
		TransportForDialing(ma.Multiaddr) transport.Transport
	}).TransportForDialing(good), "swarm must accept a well-formed alias addr")

	bad, err := ma.NewMultiaddr("/warpid/" + freshWarpID(t))
	require.NoError(t, err)
	require.Nil(t, tn.(interface {
		TransportForDialing(ma.Multiaddr) transport.Transport
	}).TransportForDialing(bad), "swarm must reject a /warpid/ with no relay prefix")
}

func TestEnableAliasServiceTwiceFails(t *testing.T) {
	h := makeHost(t, "")
	first, err := camouflage.EnableAliasService(h)
	require.NoError(t, err)
	defer first.Stop()

	_, err = camouflage.EnableAliasService(h)
	require.Error(t, err, "second EnableAliasService on same host must fail")
}

// makeDHTHost builds a host wired through the kad-dht with an isolated
// protocol prefix. aliasOnly==true strips every non-/warpid/ multiaddr
// from the host's published Addrs() — so anything a remote peer learns
// over identify/DHT can only be the alias address. The DHT is returned
// for the caller to drive Bootstrap and FindPeer.
func makeDHTHost(t *testing.T, warpID string, aliasOnly bool) (host.Host, *dht.IpfsDHT) {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	var d *dht.IpfsDHT
	opts := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(camouflage.NewCamouflageTransport),
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			var err error
			d, err = dht.New(context.Background(), h,
				dht.Mode(dht.ModeServer),
				dht.ProtocolPrefix("/warpnet-alias-test"),
			)
			return d, err
		}),
	}
	if aliasOnly {
		opts = append(opts, libp2p.AddrsFactory(func(addrs []ma.Multiaddr) []ma.Multiaddr {
			out := addrs[:0:0]
			for _, a := range addrs {
				if _, err := a.ValueForProtocol(camouflage.P_WARPID); err == nil {
					out = append(out, a)
				}
			}
			return out
		}))
	}

	h, err := libp2p.New(opts...)
	require.NoError(t, err)
	require.NoError(t, camouflage.EnableAlias(h, warpID))
	t.Cleanup(func() {
		if d != nil {
			_ = d.Close()
		}
		_ = h.Close()
	})
	return h, d
}

// makeRelayWithDHT is makeRelay's DHT-enabled twin. The relay also acts
// as the DHT server everyone bootstraps against, since this test has no
// other rendezvous.
func makeRelayWithDHT(t *testing.T) (host.Host, *aliasresolver.Resolver, *dht.IpfsDHT) {
	t.Helper()
	h, d := makeDHTHost(t, "", false)
	r, err := camouflage.EnableAliasService(h)
	require.NoError(t, err)
	t.Cleanup(r.Stop)
	return h, r, d
}

// TestAliasDiscoveryThroughRelay walks the full discovery chain end to
// end through a real Kademlia DHT — no peerstore shortcuts:
//
//  1. listener connects to the relay (which runs EnableAliasService);
//  2. listener's auto-finder sees RegisterProtocol via identify and
//     auto-Listens on /p2p/<relay>/warpid/<warpID>;
//  3. listener filters its published Addrs() down to /warpid/ only,
//     so identify-push to the relay carries the alias and nothing else;
//  4. dialer queries the DHT for listener's AddrInfo and gets back
//     the alias multiaddr;
//  5. dialer connects + opens a stream + echoes, and the established
//     connection's RemoteMultiaddr carries /warpid/.
//
// The dialer never sees the listener's IP at any point: not via
// peerstore.AddAddr, not via direct connect — only through the DHT
// answer, which is alias-only.
func TestAliasDiscoveryThroughRelay(t *testing.T) {
	warpID := freshWarpID(t)

	relayH, resolver, _ := makeRelayWithDHT(t)
	listenerH, listenerDHT := makeDHTHost(t, warpID, true)
	dialerH, dialerDHT := makeDHTHost(t, "", false)

	listenerH.SetStreamHandler(echoProtoAlias, func(s network.Stream) {
		defer s.Close()
		_, _ = io.Copy(s, s)
	})

	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 10*time.Second, 20*time.Millisecond, "listener must auto-register on the relay")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.NoError(t, listenerDHT.Bootstrap(ctx))
	require.NoError(t, dialerDHT.Bootstrap(ctx))

	// Wait until the listener's published Addrs() carry the alias and
	// only the alias — that's what identify-push will send to the relay
	// and what the DHT will then return on a FindPeer query.
	require.Eventually(t, func() bool {
		addrs := listenerH.Addrs()
		if len(addrs) == 0 {
			return false
		}
		for _, a := range addrs {
			if _, err := a.ValueForProtocol(camouflage.P_WARPID); err != nil {
				return false
			}
		}
		return true
	}, 10*time.Second, 50*time.Millisecond, "listener.Addrs() must be alias-only")

	// Hammer FindPeer until the relay's peerstore reflects the push and
	// the DHT actually returns a non-empty alias-only AddrInfo. On a
	// freshly-booted DHT this normally lands in a second or two.
	var found peer.AddrInfo
	require.Eventually(t, func() bool {
		qctx, qcancel := context.WithTimeout(ctx, 5*time.Second)
		defer qcancel()
		info, err := dialerDHT.FindPeer(qctx, listenerH.ID())
		if err != nil || len(info.Addrs) == 0 {
			return false
		}
		for _, a := range info.Addrs {
			if _, err := a.ValueForProtocol(camouflage.P_WARPID); err != nil {
				return false
			}
		}
		found = info
		return true
	}, 30*time.Second, 200*time.Millisecond, "DHT FindPeer must return alias-only AddrInfo")

	require.Equal(t, listenerH.ID(), found.ID)
	require.NotEmpty(t, found.Addrs)
	for _, a := range found.Addrs {
		v, err := a.ValueForProtocol(camouflage.P_WARPID)
		require.NoError(t, err, "DHT-returned addr %s must contain /warpid/", a)
		require.Equal(t, warpID, v)
		require.Contains(t, a.String(), relayH.ID().String(),
			"DHT-returned addr must reference the relay, got %s", a)
	}

	require.NoError(t, dialerH.Connect(ctx, found),
		"dial via the DHT-discovered alias addr must succeed")

	s, err := dialerH.NewStream(ctx, listenerH.ID(), echoProtoAlias)
	require.NoError(t, err)
	defer s.Close()

	payload := []byte("discovered-via-dht")
	_, err = s.Write(payload)
	require.NoError(t, err)
	require.NoError(t, s.CloseWrite())

	got, err := io.ReadAll(s)
	require.NoError(t, err)
	require.Equal(t, payload, got)

	require.Contains(t, s.Conn().RemoteMultiaddr().String(), "/warpid/",
		"established connection must ride a /warpid/ multiaddr, got %s",
		s.Conn().RemoteMultiaddr())
}
