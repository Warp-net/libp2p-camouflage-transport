// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package camouflage_test

import (
	"context"
	"crypto/rand"
	"io"
	"testing"
	"time"

	camouflage "github.com/Warp-net/libp2p-camouflage-transport"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

// makeAliasRelayService builds a public host that is both a circuit-v2
// relay (so a NAT'd peer can reserve through it and autorelay can hand
// out /p2p-circuit addrs) and an alias resolver. This mirrors a warpnet
// bootstrap.
func makeAliasRelayService(t *testing.T) host.Host {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(camouflage.NewCamouflageTransport),
		libp2p.EnableRelayService(),
		libp2p.ForceReachabilityPublic(),
	)
	require.NoError(t, err)
	_, err = camouflage.EnableAliasService(h)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// makeNATdAliasHost reproduces a warpnet member behind NAT: forced
// private reachability, circuit-relay client, autorelay pinned to the
// given relay as a static relay, camouflage transport, and alias mode
// with a real WarpID. This is the exact combination the deployed member
// runs — autorelay will install /p2p-circuit addrs and the question is
// whether the /warpid/ alias address survives alongside them in Addrs().
func makeNATdAliasHost(t *testing.T, warpID string, relay peer.AddrInfo) host.Host {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(camouflage.NewCamouflageTransport),
		libp2p.EnableRelay(),
		libp2p.EnableAutoRelayWithStaticRelays([]peer.AddrInfo{relay}),
		libp2p.ForceReachabilityPrivate(),
	)
	require.NoError(t, err)
	require.NoError(t, camouflage.EnableAlias(h, warpID))
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// TestAliasAddrSurvivesAutorelayPrivate is the warpnet-discovery
// regression test. The deployed symptom is: a member behind NAT
// auto-registers its WarpID on a relay, but peers never learn the alias
// address, so nobody can dial it. publishPeerInfo gossips exactly
// node.Addrs(); if the /warpid/ address is missing from Addrs() under
// real member conditions (autorelay + ForceReachabilityPrivate), the
// alias can never propagate regardless of the transport being correct.
//
// This test reproduces those conditions and asserts both that the alias
// landed on the resolver AND that it shows up in the member's published
// Addrs() next to the autorelay /p2p-circuit addresses.
func TestAliasAddrSurvivesAutorelayPrivate(t *testing.T) {
	warpID := freshWarpID(t)

	relayH := makeAliasRelayService(t)
	relayInfo := peer.AddrInfo{ID: relayH.ID(), Addrs: relayH.Addrs()}

	memberH := makeNATdAliasHost(t, warpID, relayInfo)

	// Reach the relay over plain camouflage TCP, like a member reaching
	// a bootstrap. autorelay needs this connection to reserve a slot.
	connect(t, memberH, relayH)

	// The alias must register through the auto-finder and then surface
	// in the member's published Addrs() — that is exactly what
	// publishPeerInfo gossips. This is the discovery regression guard:
	// if ForceReachabilityPrivate + autorelay strip the /warpid/ address
	// here, no peer can ever learn the alias, and discovery is dead
	// regardless of the transport being otherwise correct.
	var lastAddrs []ma.Multiaddr
	ok := waitFor(20*time.Second, 100*time.Millisecond, func() bool {
		lastAddrs = memberH.Addrs()
		return aliasInAddrs(lastAddrs, warpID)
	})
	require.Truef(t, ok,
		"the /warpid/ alias address must appear in the NAT'd member's published Addrs(); got %v", lastAddrs)
}

// TestAliasDialFromGossipedAddrs closes the discovery loop the way
// warpnet does it: a second NAT'd member learns the listener purely from
// the multiaddr the listener publishes (the same value publishPeerInfo
// gossips), with no direct IP exchange, and dials it.
func TestAliasDialFromGossipedAddrs(t *testing.T) {
	warpID := freshWarpID(t)

	relayH := makeAliasRelayService(t)
	relayInfo := peer.AddrInfo{ID: relayH.ID(), Addrs: relayH.Addrs()}

	listenerH := makeNATdAliasHost(t, warpID, relayInfo)
	listenerH.SetStreamHandler(echoProtoAlias, func(s network.Stream) {
		defer s.Close()
		_, _ = io.Copy(s, s)
	})

	dialerH := makeNATdAliasHost(t, freshWarpID(t), relayInfo)

	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	// Pull exactly what gossip would broadcast for the listener.
	var aliasAddrs []ma.Multiaddr
	require.Eventually(t, func() bool {
		aliasAddrs = aliasAddrsOf(listenerH.Addrs(), warpID)
		return len(aliasAddrs) > 0
	}, 20*time.Second, 100*time.Millisecond,
		"listener must publish a /warpid/ address for gossip")

	// The dialer learns the listener only through the gossiped alias
	// multiaddrs — never its IP.
	dialerH.Peerstore().AddAddrs(listenerH.ID(), aliasAddrs, peerstore.TempAddrTTL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := dialerH.NewStream(ctx, listenerH.ID(), echoProtoAlias)
	require.NoError(t, err, "dial via gossiped /warpid/ addr must succeed")
	defer s.Close()

	payload := []byte("gossip-discovered")
	_, err = s.Write(payload)
	require.NoError(t, err)
	require.NoError(t, s.CloseWrite())

	got, err := io.ReadAll(s)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

func waitFor(timeout, tick time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(tick)
	}
}

func aliasInAddrs(addrs []ma.Multiaddr, warpID string) bool {
	return len(aliasAddrsOf(addrs, warpID)) > 0
}

func aliasAddrsOf(addrs []ma.Multiaddr, warpID string) []ma.Multiaddr {
	var out []ma.Multiaddr
	for _, a := range addrs {
		if v, err := a.ValueForProtocol(camouflage.P_WARPID); err == nil && v == warpID {
			out = append(out, a)
		}
	}
	return out
}
