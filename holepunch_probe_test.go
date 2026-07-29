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

package camouflage

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/core/transport"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/net/upgrader"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func reuseControl(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
			return
		}
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

func freePort(t *testing.T) int {
	t.Helper()
	lc := net.ListenConfig{Control: reuseControl}
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

func simultaneousOpenPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	pA, pB := freePort(t), freePort(t)
	if pA == pB {
		t.Skip("could not get two distinct ports")
	}

	deadline := time.Now().Add(20 * time.Second)

	dialLoop := func(localPort, remotePort int, out chan<- net.Conn, stop <-chan struct{}) {
		la := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort}
		for time.Now().Before(deadline) {
			select {
			case <-stop:
				return
			default:
			}
			d := net.Dialer{LocalAddr: la, Control: reuseControl, Timeout: 300 * time.Millisecond}
			c, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort))
			if err == nil {
				out <- c
				return
			}
			time.Sleep(time.Millisecond)
		}
		out <- nil
	}

	chA, chB := make(chan net.Conn, 1), make(chan net.Conn, 1)
	stop := make(chan struct{})
	go dialLoop(pA, pB, chA, stop)
	go dialLoop(pB, pA, chB, stop)

	a, b := <-chA, <-chB
	close(stop)
	if a == nil || b == nil {
		if a != nil {
			a.Close()
		}
		if b != nil {
			b.Close()
		}
		t.Skip("could not establish TCP simultaneous open on this host")
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestHolePunch_SimultaneousOpenIsReal(t *testing.T) {
	a, b := simultaneousOpenPair(t)

	go a.Write([]byte("ping"))
	buf := make([]byte, 4)
	require.NoError(t, b.SetReadDeadline(time.Now().Add(3*time.Second)))
	n, err := b.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf[:n]))
	t.Logf("simultaneous open OK: %s <-> %s", a.LocalAddr(), b.LocalAddr())
}

func hpCamoConfig(t *testing.T) *CamouflageConfig {
	t.Helper()
	cfg, err := BuildCamouflageConfig(defaultSNI, BrowserChrome, 5*time.Second)
	require.NoError(t, err)
	return cfg
}

func TestHolePunch_CamouflageBothSidesDial(t *testing.T) {
	a, b := simultaneousOpenPair(t)
	cfg := hpCamoConfig(t)

	type res struct {
		conn *CamouflageConn
		err  error
	}
	out := make(chan res, 2)

	dialSide := func(c net.Conn) {
		mc, err := manet.WrapNetConn(c)
		if err != nil {
			out <- res{nil, err}
			return
		}
		spoofed := NewSpoofConn(mc, DefaultFragmentSize, DefaultHandshakeLen, 0)
		cc, err := NewCamouflageConn(spoofed, true, cfg)
		out <- res{cc, err}
	}

	go dialSide(a)
	go dialSide(b)

	var errs []error
	for i := 0; i < 2; i++ {
		r := <-out
		if r.err != nil {
			errs = append(errs, r.err)
		} else {
			r.conn.Close()
		}
	}

	for _, e := range errs {
		t.Logf("camouflage handshake error: %v", e)
	}
	require.NotEmpty(t, errs,
		"two TLS clients must not be able to complete a handshake, so Dial "+
			"has to derive the role from the simultaneous-connect hint")
}

func TestHolePunch_CamouflageClientServerControl(t *testing.T) {
	a, b := simultaneousOpenPair(t)
	cfg := hpCamoConfig(t)

	out := make(chan error, 2)
	run := func(c net.Conn, isClient bool) {
		mc, err := manet.WrapNetConn(c)
		if err != nil {
			out <- err
			return
		}
		spoofed := NewSpoofConn(mc, DefaultFragmentSize, DefaultHandshakeLen, 0)
		cc, err := NewCamouflageConn(spoofed, isClient, cfg)
		if cc != nil {
			defer cc.Close()
		}
		out <- err
	}
	go run(a, true)
	go run(b, false)

	for i := 0; i < 2; i++ {
		require.NoError(t, <-out,
			"client/server roles must succeed on the very same socket pair")
	}
}

func newTestUpgrader(t *testing.T) (transport.Upgrader, peer.ID) {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(nil)
	require.NoError(t, err)
	id, err := peer.IDFromPrivateKey(priv)
	require.NoError(t, err)

	muxers := []upgrader.StreamMuxer{{ID: yamux.ID, Muxer: yamux.DefaultTransport}}
	secTpt, err := noise.New(noise.ID, priv, nil)
	require.NoError(t, err)
	u, err := upgrader.New([]sec.SecureTransport{secTpt}, muxers, nil, nil, nil)
	require.NoError(t, err)
	return u, id
}

func newTestTransport(t *testing.T, u transport.Upgrader) *CamouflageTransport {
	t.Helper()
	tpt, err := NewCamouflageTransport(u, nil, nil, WithMaxDelay(0))
	require.NoError(t, err)
	return tpt
}

func upgradeHolePunched(
	tpt *CamouflageTransport,
	c net.Conn,
	remote peer.ID,
	isClient bool,
	camouflage bool,
) (transport.CapableConn, error) {
	mc, err := manet.WrapNetConn(c)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(
		network.WithSimultaneousConnect(context.Background(), isClient, "hole-punching"),
		15*time.Second,
	)
	defer cancel()

	direction := network.DirOutbound
	if ok, ic, _ := network.GetSimultaneousConnect(ctx); ok && !ic {
		direction = network.DirInbound
	}
	scope, err := (&network.NullResourceManager{}).OpenConnection(direction, true, mc.RemoteMultiaddr())
	if err != nil {
		return nil, err
	}
	if err := scope.SetPeer(remote); err != nil {
		scope.Done()
		return nil, err
	}

	var cc transport.CapableConn
	if camouflage {
		cc, err = tpt.upgradeDialed(ctx, mc, remote, scope)
	} else {
		cc, err = tpt.upgrader.Upgrade(ctx, tpt, mc, direction, remote, scope)
	}
	if err != nil {
		scope.Done()
		return nil, err
	}
	return cc, nil
}

func TestHolePunch_FullStack(t *testing.T) {
	for _, tc := range []struct {
		name       string
		camouflage bool
	}{
		{"plain_tcp_control", false},
		{"camouflage", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := simultaneousOpenPair(t)

			uA, idA := newTestUpgrader(t)
			uB, idB := newTestUpgrader(t)
			tA := newTestTransport(t, uA)
			tB := newTestTransport(t, uB)

			var wg sync.WaitGroup
			var errA, errB error
			wg.Add(2)
			go func() {
				defer wg.Done()
				c, err := upgradeHolePunched(tA, a, idB, true, tc.camouflage)
				errA = err
				if c != nil {
					c.Close()
				}
			}()
			go func() {
				defer wg.Done()
				c, err := upgradeHolePunched(tB, b, idA, false, tc.camouflage)
				errB = err
				if c != nil {
					c.Close()
				}
			}()
			wg.Wait()

			t.Logf("side A err: %v", errA)
			t.Logf("side B err: %v", errB)

			require.NoError(t, errA)
			require.NoError(t, errB)
		})
	}
}

func TestHolePunch_DefaultHandshakeLatency(t *testing.T) {
	cfg, err := BuildCamouflageConfig(defaultSNI, BrowserChrome, defaultHandshakeTimeout)
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		fragSize int
		maxDelay time.Duration
	}{
		{"package_defaults", DefaultFragmentSize, DefaultMaxDelay},
		{"no_delay", DefaultFragmentSize, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := simultaneousOpenPair(t)
			out := make(chan error, 2)
			run := func(c net.Conn, isClient bool) {
				mc, err := manet.WrapNetConn(c)
				if err != nil {
					out <- err
					return
				}
				s := NewSpoofConn(mc, tc.fragSize, DefaultHandshakeLen, tc.maxDelay)
				cc, err := NewCamouflageConn(s, isClient, cfg)
				if cc != nil {
					defer cc.Close()
				}
				out <- err
			}
			start := time.Now()
			go run(a, true)
			go run(b, false)
			for i := 0; i < 2; i++ {
				require.NoError(t, <-out)
			}
			t.Logf("camouflage handshake on loopback took %v (holepunch budget: 10s)", time.Since(start))
		})
	}
}
