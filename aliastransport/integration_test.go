// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package aliastransport_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/Warp-net/libp2p-camouflage-transport/aliasresolver"
	"github.com/Warp-net/libp2p-camouflage-transport/aliastransport"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

// makeKey returns a fresh Ed25519 keypair for use with libp2p.
func makeKey(t *testing.T) crypto.PrivKey {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(nil)
	require.NoError(t, err)
	return priv
}

// makeAliasHost returns a host wired with the alias transport. It still
// keeps the default TCP transport so it can reach the relay over plain
// TCP. The host's own private key is used to sign the WarpID.
func makeAliasHost(t *testing.T, warpID string) host.Host {
	t.Helper()
	priv := makeKey(t)
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
		libp2p.DefaultTransports,
		libp2p.Transport(aliastransport.NewFactory(priv, warpID)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// makeRelayHost starts a host that runs the resolver. It does not load
// the alias transport because the relay never dials/listens via warpid.
func makeRelayHost(t *testing.T) (host.Host, *aliasresolver.Resolver) {
	t.Helper()
	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	r := aliasresolver.New(h)
	r.Start()
	t.Cleanup(r.Stop)
	return h, r
}

// connect dials src -> dst over their default transports so that
// subsequent stream opens between them succeed without re-resolution.
func connect(t *testing.T, src, dst host.Host) {
	t.Helper()
	src.Peerstore().AddAddrs(dst.ID(), dst.Addrs(), peerstore.PermanentAddrTTL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, src.Connect(ctx, peer.AddrInfo{ID: dst.ID(), Addrs: dst.Addrs()}))
}

const echoProto protocol.ID = "/test/alias-echo/0.0.0"

func TestAliasRoundtrip(t *testing.T) {
	const warpID = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	relayH, _ := makeRelayHost(t)
	listenerH := makeAliasHost(t, warpID)
	dialerH := makeAliasHost(t, "00"+warpID[2:]) // different alias; not registered

	// Listener registers on relay; dialer needs the relay reachable
	// for the resolve stream.
	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	// Listener echo handler so we can verify bytes flow end-to-end.
	listenerH.SetStreamHandler(echoProto, func(s network.Stream) {
		defer s.Close()
		_, _ = io.Copy(s, s)
	})

	// Trigger Listen on the alias address.
	aliasAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + warpID)
	require.NoError(t, err)
	require.NoError(t, listenerH.Network().Listen(aliasAddr))

	// Give the registration time to settle.
	time.Sleep(100 * time.Millisecond)

	// Dialer addresses the listener purely by alias, never by IP.
	target, err := ma.NewMultiaddr(
		"/p2p/" + relayH.ID().String() +
			"/warpid/" + warpID +
			"/p2p/" + listenerH.ID().String(),
	)
	require.NoError(t, err)
	dialerH.Peerstore().AddAddr(listenerH.ID(), target, peerstore.TempAddrTTL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := dialerH.NewStream(ctx, listenerH.ID(), echoProto)
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
	const warpID = "ff02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1faa"

	relayH, resolver := makeRelayHost(t)
	first := makeAliasHost(t, warpID)
	second := makeAliasHost(t, warpID)

	connect(t, first, relayH)
	connect(t, second, relayH)

	aliasAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + warpID)
	require.NoError(t, err)

	require.NoError(t, first.Network().Listen(aliasAddr))
	time.Sleep(100 * time.Millisecond)

	// A different peer attempting to claim the same WarpID must fail.
	err = second.Network().Listen(aliasAddr)
	require.Error(t, err)

	// Registry still maps to the original owner.
	entry, ok := resolver.Lookup(warpID)
	require.True(t, ok)
	require.Equal(t, first.ID(), entry.Peer)
}
