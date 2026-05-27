// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package aliasresolver_test

import (
	"bufio"
	"context"
	"testing"
	"time"

	"github.com/Warp-net/libp2p-camouflage-transport/aliasresolver"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
)

func mkHost(t *testing.T) host.Host {
	t.Helper()
	h, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func dial(t *testing.T, src, dst host.Host) {
	t.Helper()
	src.Peerstore().AddAddrs(dst.ID(), dst.Addrs(), peerstore.PermanentAddrTTL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, src.Connect(ctx, peer.AddrInfo{ID: dst.ID(), Addrs: dst.Addrs()}))
}

func TestRegisterRejectsBadSignature(t *testing.T) {
	relay := mkHost(t)
	client := mkHost(t)

	r := aliasresolver.New(relay)
	r.Start()
	defer r.Stop()

	dial(t, client, relay)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := client.NewStream(ctx, relay.ID(), aliasresolver.RegisterProtocol)
	require.NoError(t, err)
	defer s.Close()

	// Send a forged registration: the signature does not match the WarpID.
	bad := aliasresolver.RegisterRequest{
		ID:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		Sig: []byte("not-a-real-signature"),
	}
	require.NoError(t, aliasresolver.WriteJSON(s, bad))

	// Relay resets the stream; reading status should give empty + EOF/closed.
	br := bufio.NewReader(s)
	status, _ := aliasresolver.ReadStatus(br)
	require.NotEqual(t, "ok", status)

	_, ok := r.Lookup(bad.ID)
	require.False(t, ok, "forged registration must not appear in the table")
}

func TestResolveUnknownIDFails(t *testing.T) {
	relay := mkHost(t)
	client := mkHost(t)

	r := aliasresolver.New(relay)
	r.Start()
	defer r.Stop()

	dial(t, client, relay)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := client.NewStream(ctx, relay.ID(), aliasresolver.ResolveProtocol)
	require.NoError(t, err)
	defer s.Close()

	require.NoError(t, aliasresolver.WriteJSON(s, aliasresolver.ResolveRequest{
		ID: "0000000000000000000000000000000000000000000000000000000000000000",
	}))

	br := bufio.NewReader(s)
	status, _ := aliasresolver.ReadStatus(br)
	require.NotEqual(t, "ok", status)
}
