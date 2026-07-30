//go:build dpilab

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

// dpilab is the node side of the DPI lab: two relay nodes on a sniffable wire,
// talking over the camouflage transport, so that nDPI can be asked what the
// traffic between them looks like. lab.sh builds the wire, captures it and runs
// the verdict; this binary only produces the traffic.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	camouflage "github.com/Warp-net/libp2p-camouflage-transport"
	"github.com/libp2p/go-libp2p"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	tcptransport "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ma "github.com/multiformats/go-multiaddr"
)

// bulkProto carries the lab's request/response traffic. A small request and a
// large response mirror the shape of a browser fetching a page over HTTPS.
const bulkProto = protocol.ID("/dpilab/bulk/1.0.0")

const (
	requestSize     = 512
	responseSize    = 192 << 10
	maxResponseSize = 1 << 20
)

// The lab runs on its own PSK, so these nodes can never talk to a real Warpnet
// network even if the sandbox around them leaks.
var labPSK = sha256.Sum256([]byte("dpilab-private-network-psk"))

func main() {
	var (
		role      = flag.String("role", "", "print-id | serve | dial | verify")
		seed      = flag.String("seed", "", "identity seed")
		ip        = flag.String("ip", "0.0.0.0", "listen address")
		port      = flag.Int("port", 4001, "listen port")
		transport = flag.String("transport", "camouflage", "camouflage | plain")
		sni       = flag.String("sni", "", "override the camouflage SNI (default: the transport's own)")
		target    = flag.String("target", "", "peer multiaddr to dial (dial role)")
		rounds    = flag.Int("rounds", 5, "how many fresh connections to open (dial role)")
		readyFile = flag.String("ready-file", "", "file to write the listen multiaddr into")
		doneFile  = flag.String("done-file", "", "file that ends the serve role")
		timeout   = flag.Duration("timeout", 3*time.Minute, "overall deadline")

		flows     = flag.String("flows", "", "ndpiReader -K json output to judge (verify role)")
		ndpiLog   = flag.String("ndpi-log", "", "ndpiReader -v 2 text output, for the client fingerprint (verify role)")
		wireA     = flag.String("wire-a", "", "first lab IP (verify role)")
		wireB     = flag.String("wire-b", "", "second lab IP (verify role)")
		minFlows  = flag.Int("min-flows", 1, "how many lab flows the capture must contain (verify role)")
		minShakes = flag.Int("min-handshakes", 1, "how many TCP handshakes the lab flows must carry (verify role)")
		expectStr = flag.String("expect", "browsing", "browsing | not-browsing (verify role)")
	)
	flag.Parse()

	if *role == "verify" {
		if err := runVerify(*flows, *ndpiLog, *wireA, *wireB, *port, *minFlows, *minShakes, *expectStr); err != nil {
			fatal(err)
		}
		return
	}

	privKey, err := identity(*seed)
	if err != nil {
		fatal(err)
	}

	if *role == "print-id" {
		id, err := peer.IDFromPrivateKey(privKey)
		if err != nil {
			fatal(err)
		}
		fmt.Println(id.String())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	h, err := newRelayNode(privKey, *ip, *port, *transport, *sni)
	if err != nil {
		fatal(err)
	}
	defer h.Close()

	logf("node up id=%s transport=%s addrs=%v", h.ID(), *transport, h.Addrs())

	switch *role {
	case "serve":
		err = serve(ctx, h, *ip, *port, *readyFile, *doneFile)
	case "dial":
		err = dial(ctx, h, *target, *rounds)
	default:
		err = fmt.Errorf("unknown role %q", *role)
	}
	if err != nil {
		logf("RESULT=FAIL %v", err)
		fatal(err)
	}
	logf("RESULT=PASS")
}

// newRelayNode builds a libp2p relay node. Everything a Warpnet node puts on
// the wire is here - the camouflage transport with its shipped defaults, Noise
// inside it, a PSK, and the circuit v2 hop service - and nothing that would
// change what a DPI box sees is left out.
func newRelayNode(privKey p2pcrypto.PrivKey, ip string, port int, transportName, sni string) (host.Host, error) {
	var transportOpt libp2p.Option
	switch transportName {
	case "camouflage":
		// The shipped defaults are what has to survive nDPI, so the SNI is the
		// only knob the lab touches - overriding it is how the risk table is
		// shown not to be dead code.
		if sni == "" {
			transportOpt = libp2p.Transport(camouflage.NewCamouflageTransport)
		} else {
			transportOpt = libp2p.Transport(camouflage.NewCamouflageTransport, camouflage.WithSNI(sni))
		}
	case "plain":
		// The control arm: the same libp2p stack with the stock TCP transport,
		// so the verdict is measured against traffic that is *not* camouflaged.
		transportOpt = libp2p.Transport(tcptransport.NewTCPTransport)
	default:
		return nil, fmt.Errorf("unknown transport %q", transportName)
	}

	return libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/%s/tcp/%d", ip, port)),
		transportOpt,
		libp2p.Security(noise.ID, noise.New),
		libp2p.PrivateNetwork(labPSK[:]),
		libp2p.Ping(true),
		libp2p.EnableRelay(),
		libp2p.EnableRelayService(),
		// A relay serves circuit v2 only once AutoNAT reports public
		// reachability; there is no AutoNAT server on this wire, so state it.
		libp2p.ForceReachabilityPublic(),
	)
}

// serve answers bulk requests until the done file appears.
func serve(ctx context.Context, h host.Host, ip string, port int, readyFile, doneFile string) error {
	h.SetStreamHandler(bulkProto, func(s network.Stream) {
		defer s.Close()
		if err := answer(s); err != nil {
			logf("bulk stream failed: %v", err)
			_ = s.Reset()
		}
	})

	if readyFile != "" {
		maddr := fmt.Sprintf("/ip4/%s/tcp/%d/p2p/%s", ip, port, h.ID())
		if err := os.WriteFile(readyFile, []byte(maddr+"\n"), 0o644); err != nil {
			return err
		}
		logf("listening maddr=%s", maddr)
	}

	for {
		if doneFile != "" {
			if _, err := os.Stat(doneFile); err == nil {
				logf("peer reported done")
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("serve: %w", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// answer reads a request and writes responseSize bytes back, the way a server
// answers a browser: a short request in, a page-sized body out.
func answer(s network.Stream) error {
	var reqLen uint32
	if err := binary.Read(s, binary.BigEndian, &reqLen); err != nil {
		return err
	}
	if reqLen > maxResponseSize {
		return fmt.Errorf("request too large: %d", reqLen)
	}
	if _, err := io.CopyN(io.Discard, s, int64(reqLen)); err != nil {
		return err
	}

	body := make([]byte, responseSize)
	if _, err := rand.Read(body); err != nil {
		return err
	}
	if err := binary.Write(s, binary.BigEndian, uint32(len(body))); err != nil {
		return err
	}
	_, err := s.Write(body)
	return err
}

// dial opens `rounds` independent connections to the target, each one carrying
// identify, a ping and a bulk transfer, then tears it down. Every round is a
// fresh TCP flow, so nDPI gets a handful of separate sessions to classify
// instead of one long-lived connection.
func dial(ctx context.Context, h host.Host, target string, rounds int) error {
	if target == "" {
		return errors.New("dial: -target is required")
	}
	maddr, err := ma.NewMultiaddr(target)
	if err != nil {
		return err
	}
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return err
	}

	pinger := ping.NewPingService(h)

	for i := 1; i <= rounds; i++ {
		if err := round(ctx, h, pinger, *info, i); err != nil {
			return fmt.Errorf("round %d: %w", i, err)
		}
		if err := h.Network().ClosePeer(info.ID); err != nil {
			return fmt.Errorf("round %d: close: %w", i, err)
		}
		h.Peerstore().ClearAddrs(info.ID)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil
}

func round(ctx context.Context, h host.Host, pinger *ping.PingService, info peer.AddrInfo, n int) error {
	dialCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	if err := h.Connect(dialCtx, info); err != nil {
		return err
	}

	res := <-pinger.Ping(dialCtx, info.ID)
	if res.Error != nil {
		return fmt.Errorf("ping: %w", res.Error)
	}

	// A reservation on the peer's hop service: these are relay nodes, so make
	// them speak circuit v2 to each other and not just identify and ping.
	if n == 1 {
		if _, err := client.Reserve(dialCtx, h, info); err != nil {
			return fmt.Errorf("reserve: %w", err)
		}
		logf("event=reservation peer=%s", info.ID)
	}

	got, err := fetch(dialCtx, h, info.ID)
	if err != nil {
		return err
	}
	logf("event=transfer round=%d bytes=%d rtt=%s", n, got, res.RTT)
	return nil
}

func fetch(ctx context.Context, h host.Host, id peer.ID) (int, error) {
	s, err := h.NewStream(ctx, id, bulkProto)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	if err := s.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, err
	}

	req := make([]byte, requestSize)
	if _, err := rand.Read(req); err != nil {
		return 0, err
	}
	if err := binary.Write(s, binary.BigEndian, uint32(len(req))); err != nil {
		return 0, err
	}
	if _, err := s.Write(req); err != nil {
		return 0, err
	}
	if err := s.CloseWrite(); err != nil {
		return 0, err
	}

	var respLen uint32
	if err := binary.Read(s, binary.BigEndian, &respLen); err != nil {
		return 0, err
	}
	if respLen > maxResponseSize {
		return 0, fmt.Errorf("response too large: %d", respLen)
	}
	n, err := io.CopyN(io.Discard, s, int64(respLen))
	return int(n), err
}

// identity derives a deterministic key from a seed, so lab.sh can learn a
// node's peer ID before starting it.
func identity(seed string) (p2pcrypto.PrivKey, error) {
	if seed == "" {
		return nil, errors.New("-seed is required")
	}
	sum := sha256.Sum256([]byte(seed))
	return p2pcrypto.UnmarshalEd25519PrivateKey(ed25519.NewKeyFromSeed(sum[:]))
}

func logf(format string, args ...any) {
	fmt.Printf("DPILAB "+format+"\n", args...)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "DPILAB fatal: %v\n", err)
	os.Exit(1)
}
