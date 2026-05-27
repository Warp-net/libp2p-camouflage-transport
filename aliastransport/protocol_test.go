// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package aliastransport

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func randomWarpID(t *testing.T) string {
	t.Helper()
	b := make([]byte, WarpIDByteLen)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

func TestWarpIDProtocolRegistered(t *testing.T) {
	p := ma.ProtocolWithCode(P_WARPID)
	require.Equal(t, WarpIDName, p.Name)
	require.Equal(t, P_WARPID, p.Code)
}

func TestWarpIDRoundtrip(t *testing.T) {
	id := randomWarpID(t)
	addr, err := ma.NewMultiaddr("/warpid/" + id)
	require.NoError(t, err)

	v, err := addr.ValueForProtocol(P_WARPID)
	require.NoError(t, err)
	require.Equal(t, id, v)

	// Bytes round-trip.
	b := addr.Bytes()
	addr2, err := ma.NewMultiaddrBytes(b)
	require.NoError(t, err)
	require.Equal(t, addr.String(), addr2.String())
}

func TestWarpIDRejectsBadLength(t *testing.T) {
	_, err := ma.NewMultiaddr("/warpid/" + strings.Repeat("ab", 10)) // 20 bytes
	require.Error(t, err)
}

func TestWarpIDRejectsNonHex(t *testing.T) {
	_, err := ma.NewMultiaddr("/warpid/" + strings.Repeat("zz", WarpIDByteLen))
	require.Error(t, err)
}

func TestSplitDialAddr(t *testing.T) {
	id := randomWarpID(t)
	relay := "12D3KooWBhTEpqNvjoTPxF5JsDmGW1zUmu5xZsMRoXcZQ4WPJjkx"
	dest := "12D3KooWCFsgVE1S46QbQYbHbWqznKQYrJB6vQ2qj6mFL6sBQHtt"

	addr, err := ma.NewMultiaddr("/p2p/" + relay + "/warpid/" + id + "/p2p/" + dest)
	require.NoError(t, err)

	relayID, warpID, err := splitDialAddr(addr)
	require.NoError(t, err)
	require.Equal(t, relay, relayID.String())
	require.Equal(t, id, warpID)
}

func TestSplitListenAddrRejectsTrailingP2P(t *testing.T) {
	id := randomWarpID(t)
	relay := "12D3KooWBhTEpqNvjoTPxF5JsDmGW1zUmu5xZsMRoXcZQ4WPJjkx"
	dest := "12D3KooWCFsgVE1S46QbQYbHbWqznKQYrJB6vQ2qj6mFL6sBQHtt"

	addr, err := ma.NewMultiaddr("/p2p/" + relay + "/warpid/" + id + "/p2p/" + dest)
	require.NoError(t, err)

	_, _, err = splitListenAddr(addr)
	require.Error(t, err)
}

func TestSplitListenAddrOK(t *testing.T) {
	id := randomWarpID(t)
	relay := "12D3KooWBhTEpqNvjoTPxF5JsDmGW1zUmu5xZsMRoXcZQ4WPJjkx"

	addr, err := ma.NewMultiaddr("/p2p/" + relay + "/warpid/" + id)
	require.NoError(t, err)

	relayID, warpID, err := splitListenAddr(addr)
	require.NoError(t, err)
	require.Equal(t, relay, relayID.String())
	require.Equal(t, id, warpID)
}

func TestCanDial(t *testing.T) {
	id := randomWarpID(t)
	relay := "12D3KooWBhTEpqNvjoTPxF5JsDmGW1zUmu5xZsMRoXcZQ4WPJjkx"

	good, err := ma.NewMultiaddr("/p2p/" + relay + "/warpid/" + id)
	require.NoError(t, err)
	bad, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/4001")
	require.NoError(t, err)

	tr := &Transport{}
	require.True(t, tr.CanDial(good))
	require.False(t, tr.CanDial(bad))
}
