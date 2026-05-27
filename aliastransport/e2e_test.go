// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package aliastransport_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/Warp-net/libp2p-camouflage-transport/aliasresolver"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

// freshWarpID generates a random 32-byte hex string suitable as a WarpID.
func freshWarpID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

const echoProtoE2E protocol.ID = "/test/alias-echo-e2e/0.0.0"

func bufioReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

func TestAliasManyConcurrentDials(t *testing.T) {
	warpID := freshWarpID(t)

	relayH, resolver := makeRelayHost(t)
	listenerH := makeAliasHost(t, warpID)
	dialerH := makeAliasHost(t, freshWarpID(t))

	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	listenerH.SetStreamHandler(echoProtoE2E, func(s network.Stream) {
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
		"/p2p/" + relayH.ID().String() +
			"/warpid/" + warpID +
			"/p2p/" + listenerH.ID().String(),
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
			s, err := dialerH.NewStream(ctx, listenerH.ID(), echoProtoE2E)
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

	relayH, resolver := makeRelayHost(t)
	listenerH := makeAliasHost(t, warpID)
	dialerH := makeAliasHost(t, freshWarpID(t))

	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	listenerH.SetStreamHandler(echoProtoE2E, func(s network.Stream) {
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
	s, err := dialerH.NewStream(ctx, listenerH.ID(), echoProtoE2E)
	require.NoError(t, err)
	defer s.Close()

	// 512 KiB payload exercises multiple read/write cycles inside the
	// relay's pipe goroutines.
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
	relayH, resolver := makeRelayHost(t)
	listenerH := makeAliasHost(t, warpID)

	connect(t, listenerH, relayH)

	listenAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + warpID)
	require.NoError(t, err)
	require.NoError(t, listenerH.Network().Listen(listenAddr))
	require.Eventually(t, func() bool {
		_, ok := resolver.Lookup(warpID)
		return ok
	}, 2*time.Second, 20*time.Millisecond)

	entry1, _ := resolver.Lookup(warpID)

	// Re-register from the same peer over a fresh stream. The resolver
	// must accept it because the owning public key still matches.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	priv := listenerH.Peerstore().PrivKey(listenerH.ID())
	require.NotNil(t, priv)
	sig, err := priv.Sign([]byte(warpID))
	require.NoError(t, err)

	rs, err := listenerH.NewStream(ctx, relayH.ID(), aliasresolver.RegisterProtocol)
	require.NoError(t, err)
	require.NoError(t, aliasresolver.WriteJSON(rs, aliasresolver.RegisterRequest{ID: warpID, Sig: sig}))
	br := bufioReader(rs)
	status, _ := aliasresolver.ReadStatus(br)
	require.Equal(t, "ok", status)
	_ = rs.Close()

	entry2, ok := resolver.Lookup(warpID)
	require.True(t, ok)
	require.Equal(t, entry1.Peer, entry2.Peer)
}

func TestDialUnknownWarpIDFails(t *testing.T) {
	known := freshWarpID(t)
	unknown := freshWarpID(t)

	relayH, _ := makeRelayHost(t)
	listenerH := makeAliasHost(t, known)
	dialerH := makeAliasHost(t, freshWarpID(t))

	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	listenAddr, err := ma.NewMultiaddr("/p2p/" + relayH.ID().String() + "/warpid/" + known)
	require.NoError(t, err)
	require.NoError(t, listenerH.Network().Listen(listenAddr))

	// Address a peer with a WarpID nobody registered.
	target, err := ma.NewMultiaddr(
		"/p2p/" + relayH.ID().String() + "/warpid/" + unknown + "/p2p/" + listenerH.ID().String(),
	)
	require.NoError(t, err)
	dialerH.Peerstore().AddAddr(listenerH.ID(), target, peerstore.TempAddrTTL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = dialerH.NewStream(ctx, listenerH.ID(), echoProtoE2E)
	require.Error(t, err)
}

func TestDialAfterListenerCloseFails(t *testing.T) {
	warpID := freshWarpID(t)

	relayH, resolver := makeRelayHost(t)
	listenerH := makeAliasHost(t, warpID)
	dialerH := makeAliasHost(t, freshWarpID(t))

	connect(t, listenerH, relayH)
	connect(t, dialerH, relayH)

	listenerH.SetStreamHandler(echoProtoE2E, func(s network.Stream) {
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

	// Closing the listener host kills the libp2p connection to the relay,
	// so the relay's later attempt to open a stop-stream upstream fails.
	require.NoError(t, listenerH.Close())

	target, err := ma.NewMultiaddr(
		"/p2p/" + relayH.ID().String() + "/warpid/" + warpID + "/p2p/" + listenerH.ID().String(),
	)
	require.NoError(t, err)
	dialerH.Peerstore().AddAddr(listenerH.ID(), target, peerstore.TempAddrTTL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = dialerH.NewStream(ctx, listenerH.ID(), echoProtoE2E)
	require.Error(t, err, "dial should fail once the listener has gone away")
	require.True(t, err != nil && !errors.Is(err, context.Canceled))
}
