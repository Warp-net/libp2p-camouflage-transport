//go:build natlab

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

package main

// This file mirrors the host configuration a Warpnet node ships with, so the
// harness can exercise the real thing without importing warpnet - which it
// cannot do anyway, since warpnet depends on this module.
//
// Everything below is the same libp2p behaviour as warpnet's
// core/node.CommonOptions, expressed through public libp2p APIs:
//
//   warpnet                                        here
//   node.DefaultTimeout                            labDialTimeout
//   node.WithDialTimeout/WithDialTimeoutLocal       swarm.WithDialTimeout/Local
//     (warpnet reaches the same swarm fields through reflection)
//   warpnet.NoiseID / warpnet.NewNoise              noise.ID / noise.New
//   core/relay.DefaultResources                     labRelayResources
//   node.EnableAutoRelayWithStaticRelays            staticRelays
//   node.WarpIdentity + security.GenerateKeyFromSeed labIdentity
//   security.GeneratePSK(network, version)           labPSK
//
// If a change to CommonOptions ever matters to hole punching, it has to be
// reflected here too.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	camouflage "github.com/Warp-net/libp2p-camouflage-transport"
	"github.com/libp2p/go-libp2p"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/host/autorelay"
	"github.com/libp2p/go-libp2p/p2p/host/observedaddrs"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	relayv2 "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	ma "github.com/multiformats/go-multiaddr"
)

// labDialTimeout is warpnet's node.DefaultTimeout.
const labDialTimeout = 60 * time.Second

// The lab runs on its own PSK. What matters for hole punching is that a PSK is
// configured at all - libp2p then refuses to hand the transport a shared TCP
// listener, which is the condition the harness was built to catch - not which
// bytes it carries. Production derives them from network and version; deriving
// them from a lab constant instead also guarantees these nodes can never join
// mainnet or testnet.
var labPSK = sha256.Sum256([]byte("natlab-private-network-psk"))

func init() {
	// warpnet sets this from core/node's init().
	observedaddrs.ActivationThresh = 2
}

// labRelayResources mirrors warpnet's core/relay.DefaultResources.
var labRelayResources = relayv2.Resources{
	Limit: &relayv2.RelayLimit{
		Duration: 5 * time.Minute,
		Data:     32 << 20,
	},

	ReservationTTL: time.Hour,

	MaxReservations: 128,
	MaxCircuits:     16,
	BufferSize:      4096,

	MaxReservationsPerIP:  8,
	MaxReservationsPerASN: 32,
}

// commonOptions is warpnet's node.CommonOptions. Hole punching is enabled
// without a tracer here; newHost re-applies it with the lab's tracer, exactly
// as the production list leaves room for.
func commonOptions() []libp2p.Option {
	return []libp2p.Option{
		libp2p.WithDialTimeout(labDialTimeout),
		libp2p.SwarmOpts(
			swarm.WithDialTimeout(labDialTimeout),
			swarm.WithDialTimeoutLocal(labDialTimeout),
		),
		libp2p.Transport(camouflage.NewCamouflageTransport),
		libp2p.Ping(true),
		libp2p.Security(noise.ID, noise.New),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableRelay(),
		libp2p.EnableRelayService(relayv2.WithResources(labRelayResources)),
		libp2p.EnableHolePunching(),
		libp2p.EnableNATService(),
		libp2p.NATPortMap(),
	}
}

// staticRelays mirrors node.EnableAutoRelayWithStaticRelays, including its
// removal of the node itself from the relay list.
func staticRelays(static []peer.AddrInfo, self peer.ID) libp2p.Option {
	for i, info := range static {
		if info.ID == self {
			static = slices.Delete(static, i, i+1)
			break
		}
	}
	if len(static) == 0 {
		return func(*libp2p.Config) error { return nil }
	}
	return libp2p.EnableAutoRelayWithStaticRelays(
		static,
		autorelay.WithBackoff(5*time.Minute),
		autorelay.WithMaxCandidateAge(5*time.Minute),
	)
}

// labIdentity derives a deterministic key from a seed, so topology.sh can learn
// a peer's ID before starting it. warpnet's security.GenerateKeyFromSeed hashes
// the seed with a key-type marker; the lab only needs determinism.
func labIdentity(seed string) (p2pcrypto.PrivKey, error) {
	if seed == "" {
		return nil, errors.New("identity: empty seed")
	}
	sum := sha256.Sum256([]byte(seed))
	return p2pcrypto.UnmarshalEd25519PrivateKey(ed25519.NewKeyFromSeed(sum[:]))
}

// isRelayAddr is warpnet.IsRelayMultiaddress.
func isRelayAddr(maddr ma.Multiaddr) bool {
	return strings.Contains(maddr.String(), "p2p-circuit")
}
