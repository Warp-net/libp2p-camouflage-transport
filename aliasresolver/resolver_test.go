// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package aliasresolver_test

import (
	"bytes"
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
	badID := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	require.NoError(t, aliasresolver.WriteRegisterFrame(s, badID, []byte("not-a-real-signature")))

	// Relay resets the stream after seeing the bad signature.
	_, _ = aliasresolver.ReadStatus(s) // ignore error: stream may be reset

	_, ok := r.Lookup(badID)
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

	require.NoError(t, aliasresolver.WriteResolveFrame(s,
		"0000000000000000000000000000000000000000000000000000000000000000"))

	ok, _ := aliasresolver.ReadStatus(s)
	require.False(t, ok)
}

func TestRegisterFrameRoundtrip(t *testing.T) {
	id := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	sig := []byte("signature-bytes")

	var buf bytes.Buffer
	require.NoError(t, aliasresolver.WriteRegisterFrame(&buf, id, sig))

	gotID, gotSig, err := aliasresolver.ReadRegisterFrame(&buf)
	require.NoError(t, err)
	require.Equal(t, id, gotID)
	require.Equal(t, sig, gotSig)
}

func TestResolveFrameRoundtrip(t *testing.T) {
	id := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	var buf bytes.Buffer
	require.NoError(t, aliasresolver.WriteResolveFrame(&buf, id))

	got, err := aliasresolver.ReadResolveFrame(&buf)
	require.NoError(t, err)
	require.Equal(t, id, got)
}

func TestWriteRegisterFrameRejectsBadHex(t *testing.T) {
	var buf bytes.Buffer
	err := aliasresolver.WriteRegisterFrame(&buf, "tooshort", []byte("sig"))
	require.ErrorIs(t, err, aliasresolver.ErrInvalidWarpIDHex)
}

func TestReadRegisterFrameRejectsZeroSig(t *testing.T) {
	id := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	// Hand-craft a frame with sigLen=0.
	var buf bytes.Buffer
	require.NoError(t, aliasresolver.WriteResolveFrame(&buf, id)) // 32 bytes
	buf.Write([]byte{0, 0})                                       // sigLen = 0

	_, _, err := aliasresolver.ReadRegisterFrame(&buf)
	require.Error(t, err)
}
