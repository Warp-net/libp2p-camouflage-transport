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
	"github.com/libp2p/go-libp2p/core/transport"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
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

// makeHost spins up a libp2p host configured with CamouflageTransport.
// When warpID is empty the host is alias-mode dial-only (relay & dialer
// in the e2e tests use this).
func makeHost(t *testing.T, warpID string) host.Host {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	var opts []any
	if warpID != "" {
		opts = append(opts, camouflage.WithWarpID(warpID))
	}
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(camouflage.NewCamouflageTransport, opts...),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// makeRelay wires CamouflageTransport on the relay too, so listeners
// and dialers can reach it via the DPI-resistant TLS leg. The relay
// itself never registers an alias.
func makeRelay(t *testing.T) (host.Host, *aliasresolver.Resolver) {
	t.Helper()
	h := makeHost(t, "")
	r := aliasresolver.New(h)
	r.Start()
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

	aliasAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + warpID)
	require.NoError(t, err)
	require.NoError(t, listenerH.Network().Listen(aliasAddr))

	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 2*time.Second, 20*time.Millisecond)

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

	connect(t, first, relayH)
	connect(t, second, relayH)

	aliasAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + warpID)
	require.NoError(t, err)

	require.NoError(t, first.Network().Listen(aliasAddr))
	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 2*time.Second, 20*time.Millisecond)

	err = second.Network().Listen(aliasAddr)
	require.Error(t, err)

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

	listenAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + warpID)
	require.NoError(t, err)
	require.NoError(t, listenerH.Network().Listen(listenAddr))
	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 2*time.Second, 20*time.Millisecond)

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

	listenAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + warpID)
	require.NoError(t, err)
	require.NoError(t, listenerH.Network().Listen(listenAddr))
	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 2*time.Second, 20*time.Millisecond)

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

	listenAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + warpID)
	require.NoError(t, err)
	require.NoError(t, listenerH.Network().Listen(listenAddr))
	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 2*time.Second, 20*time.Millisecond)

	entry1, _ := resolver.Lookup(warpID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	priv := listenerH.Peerstore().PrivKey(listenerH.ID())
	require.NotNil(t, priv)
	sig, err := priv.Sign([]byte(warpID))
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

	listenAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + known)
	require.NoError(t, err)
	require.NoError(t, listenerH.Network().Listen(listenAddr))

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

	listenAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + warpID)
	require.NoError(t, err)
	require.NoError(t, listenerH.Network().Listen(listenAddr))
	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 2*time.Second, 20*time.Millisecond)

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
