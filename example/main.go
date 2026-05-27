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

// Command example demonstrates how to wire the alias transport into a
// libp2p node. It supports three modes:
//
//	example relay      [--listen=<multiaddr>]
//	example listener   --relay=<full-multiaddr> --warpid=<hex>
//	example dialer     --relay=<full-multiaddr> --warpid=<hex> --peer=<peerID>
//
// The relay needs no transport-side configuration: it just runs the
// alias resolver. Both listener and dialer attach the alias transport
// via libp2p.Transport(aliastransport.NewFactory(privKey, warpID)).
//
// Example flow in three terminals (one machine):
//
//	# terminal 1 – relay
//	$ go run ./example relay
//	relay listening on /ip4/127.0.0.1/tcp/4001/p2p/12D3Koo...
//
//	# terminal 2 – listener (publishes only the alias multiaddr)
//	$ go run ./example listener \
//	    --relay /ip4/127.0.0.1/tcp/4001/p2p/12D3Koo... \
//	    --warpid 0123...32-byte-hex...
//	listener id 12D3Koo... advertising /p2p/<relay>/warpid/<id>
//	waiting for echo connections...
//
//	# terminal 3 – dialer
//	$ go run ./example dialer \
//	    --relay /ip4/127.0.0.1/tcp/4001/p2p/12D3Koo... \
//	    --warpid 0123...32-byte-hex... \
//	    --peer 12D3Koo... (listener id)
//	-> hello via warpid
//	<- hello via warpid
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Warp-net/libp2p-camouflage-transport/aliasresolver"
	"github.com/Warp-net/libp2p-camouflage-transport/aliastransport"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
)

// echoProto is the application-level stream protocol used by the
// example. It runs end-to-end (encrypted) between dialer and listener;
// the relay never decrypts it.
const echoProto protocol.ID = "/example/alias-echo/0.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	mode := os.Args[1]
	args := os.Args[2:]

	switch mode {
	case "relay":
		runRelay(args)
	case "listener":
		runListener(args)
	case "dialer":
		runDialer(args)
	case "genkey":
		runGenKey()
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n\n", mode)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: example <mode> [flags]

modes:
  relay      run an alias-resolver relay (default listen /ip4/0.0.0.0/tcp/0)
  listener   register a WarpID on a relay and accept inbound echo streams
  dialer     dial a WarpID through a relay and exchange one echo message
  genkey     emit a random 32-byte hex WarpID

run 'example <mode> -h' for the flags of a single mode.
`)
}

// runRelay starts a libp2p host whose only job is to serve the alias
// resolver. It deliberately does NOT install the alias transport because
// the relay neither dials nor listens via /warpid/.
func runRelay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	listen := fs.String("listen", "/ip4/0.0.0.0/tcp/0", "libp2p listen multiaddr")
	_ = fs.Parse(args)

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(*listen),
		libp2p.DisableRelay(),
	)
	must(err)
	defer h.Close()

	resolver := aliasresolver.New(h)
	resolver.Start()
	defer resolver.Stop()

	for _, a := range h.Addrs() {
		fmt.Printf("relay listening on %s/p2p/%s\n", a, h.ID())
	}
	waitForSignal()
}

// runListener wires the alias transport into a libp2p host, connects to
// the relay, and calls Network().Listen on the alias address. The host's
// own private key is reused to sign the WarpID — that is what proves to
// the relay that this peer owns the alias.
func runListener(args []string) {
	fs := flag.NewFlagSet("listener", flag.ExitOnError)
	relayAddr := fs.String("relay", "", "full multiaddr of the relay, including /p2p/<id>")
	warpID := fs.String("warpid", "", "32-byte hex WarpID (generate with 'example genkey')")
	listen := fs.String("listen", "/ip4/0.0.0.0/tcp/0", "underlying TCP listen multiaddr")
	_ = fs.Parse(args)
	if *relayAddr == "" || *warpID == "" {
		fs.Usage()
		os.Exit(2)
	}
	if err := validateWarpID(*warpID); err != nil {
		log.Fatalf("invalid --warpid: %v", err)
	}

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	must(err)

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(*listen),
		libp2p.DisableRelay(),
		libp2p.DefaultTransports,
		libp2p.Transport(aliastransport.NewFactory(priv, *warpID)),
	)
	must(err)
	defer h.Close()

	// The echo handler runs inside an end-to-end secure libp2p stream;
	// the relay never sees plaintext.
	h.SetStreamHandler(echoProto, func(s network.Stream) {
		defer s.Close()
		log.Printf("echo: stream from %s", s.Conn().RemotePeer())
		_, _ = io.Copy(s, s)
	})

	relayInfo := mustAddrInfo(*relayAddr)
	h.Peerstore().AddAddrs(relayInfo.ID, relayInfo.Addrs, peerstore.PermanentAddrTTL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	must(h.Connect(ctx, *relayInfo))
	cancel()

	aliasAddr := mustMultiaddr("/p2p/" + relayInfo.ID.String() + "/warpid/" + *warpID)
	must(h.Network().Listen(aliasAddr))

	fmt.Printf("listener id   %s\n", h.ID())
	fmt.Printf("listener addr %s\n", aliasAddr)
	fmt.Println("waiting for echo connections... (Ctrl-C to quit)")
	waitForSignal()
}

// runDialer demonstrates the dial path. The dialer never learns the
// listener's IP: it only sees the relay's address plus the alias.
func runDialer(args []string) {
	fs := flag.NewFlagSet("dialer", flag.ExitOnError)
	relayAddr := fs.String("relay", "", "full multiaddr of the relay, including /p2p/<id>")
	warpID := fs.String("warpid", "", "32-byte hex WarpID of the target peer")
	peerID := fs.String("peer", "", "libp2p peer id of the target (printed by the listener)")
	message := fs.String("msg", "hello via warpid", "payload to send")
	_ = fs.Parse(args)
	if *relayAddr == "" || *warpID == "" || *peerID == "" {
		fs.Usage()
		os.Exit(2)
	}
	if err := validateWarpID(*warpID); err != nil {
		log.Fatalf("invalid --warpid: %v", err)
	}

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	must(err)

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
		libp2p.DisableRelay(),
		libp2p.DefaultTransports,
		// The dialer's own WarpID is unused (we never call Listen) but
		// the factory still needs one — supplying a zero-derived dummy
		// keeps the api symmetric.
		libp2p.Transport(aliastransport.NewFactory(priv, dummyWarpID())),
	)
	must(err)
	defer h.Close()

	relayInfo := mustAddrInfo(*relayAddr)
	h.Peerstore().AddAddrs(relayInfo.ID, relayInfo.Addrs, peerstore.PermanentAddrTTL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	must(h.Connect(ctx, *relayInfo))
	cancel()

	target, err := peer.Decode(*peerID)
	must(err)

	// The whole point: address the target by alias only.
	aliasAddr := mustMultiaddr(
		"/p2p/" + relayInfo.ID.String() +
			"/warpid/" + *warpID +
			"/p2p/" + target.String(),
	)
	h.Peerstore().AddAddr(target, aliasAddr, peerstore.TempAddrTTL)

	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := h.NewStream(ctx, target, echoProto)
	must(err)
	defer s.Close()

	fmt.Printf("-> %s\n", *message)
	_, err = s.Write([]byte(*message))
	must(err)
	must(s.CloseWrite())

	got, err := io.ReadAll(bufio.NewReader(s))
	must(err)
	fmt.Printf("<- %s\n", string(got))
}

// runGenKey prints a fresh random 32-byte hex WarpID. Persist it
// alongside the node's identity if you want a stable alias.
func runGenKey() {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(b))
}

func dummyWarpID() string {
	// All-zero alias; never registered, never resolved.
	return strings.Repeat("00", 32)
}

func validateWarpID(s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return fmt.Errorf("expected 32 bytes (64 hex chars), got %d", len(b))
	}
	return nil
}

func mustAddrInfo(s string) *peer.AddrInfo {
	a := mustMultiaddr(s)
	ai, err := peer.AddrInfoFromP2pAddr(a)
	must(err)
	return ai
}

func mustMultiaddr(s string) ma.Multiaddr {
	a, err := ma.NewMultiaddr(s)
	must(err)
	return a
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}
