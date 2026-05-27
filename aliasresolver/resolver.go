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

// Package aliasresolver runs on relay peers. It maintains an in-memory
// table of WarpID -> owning peer, accepts signed registrations from
// listeners, and proxies inbound resolve requests onto the registered
// listener over a side-channel stream. The relay sees ciphertext only:
// dialer and listener run their own libp2p security handshake inside the
// forwarded stream.
package aliasresolver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// Wire protocols spoken by the resolver. Versions are bumped if the
// register/resolve framing or fields change incompatibly.
const (
	RegisterProtocol protocol.ID = "/warpnet/alias-register/0.0.0"
	ResolveProtocol  protocol.ID = "/warpnet/alias-resolve/0.0.0"
	// StopProtocol is the stream the relay opens *back* to a registered
	// listener once a dialer asks to resolve its WarpID. Bytes are then
	// piped between dialer and listener; both ends run their own Noise
	// handshake inside.
	StopProtocol protocol.ID = "/warpnet/alias-stop/0.0.0"
)

// statusOK is the one-line acknowledgement the relay writes after a
// successful register or before the byte-piping phase of resolve.
const statusOK = "ok"

const (
	handshakeTimeout = 10 * time.Second
	maxFrameSize     = 4 * 1024
)

// RegisterRequest is the JSON payload sent by a listener over
// RegisterProtocol. Sig is the libp2p crypto.PrivKey signature over the
// raw bytes of ID and is verified against the stream's RemotePublicKey.
type RegisterRequest struct {
	ID  string `json:"id"`
	Sig []byte `json:"sig"`
}

// ResolveRequest is sent by a dialer over ResolveProtocol.
type ResolveRequest struct {
	ID string `json:"id"`
}

// Entry is a single row of the resolver table.
type Entry struct {
	Peer  peer.ID
	Owner crypto.PubKey
}

// Resolver keeps an in-memory WarpID -> peer mapping for a single relay
// host. A WarpID is owned by the public key that first registered it; a
// subsequent registration with a different key is rejected.
type Resolver struct {
	host host.Host

	mu    sync.RWMutex
	table map[string]Entry
}

// New returns an unstarted Resolver. Call Start to wire up stream
// handlers on the host.
func New(h host.Host) *Resolver {
	return &Resolver{
		host:  h,
		table: make(map[string]Entry),
	}
}

// Start registers the resolver's stream handlers on the host. Safe to
// call once per Resolver.
func (r *Resolver) Start() {
	r.host.SetStreamHandler(RegisterProtocol, r.HandleRegister)
	r.host.SetStreamHandler(ResolveProtocol, r.HandleResolve)
}

// Stop removes the resolver's stream handlers and clears the table.
func (r *Resolver) Stop() {
	r.host.RemoveStreamHandler(RegisterProtocol)
	r.host.RemoveStreamHandler(ResolveProtocol)
	r.mu.Lock()
	r.table = make(map[string]Entry)
	r.mu.Unlock()
}

// Lookup returns the registered entry for id, if any. Intended for tests
// and diagnostics.
func (r *Resolver) Lookup(id string) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.table[id]
	return e, ok
}

// HandleRegister processes one RegisterRequest from a listener.
//
// The stream's RemotePublicKey is the source of truth for ownership;
// because the connection is libp2p-secure, the relay can trust it. The
// signature ties the WarpID to the same key, ruling out third parties
// who might capture and replay the JSON payload over their own connection.
func (r *Resolver) HandleRegister(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(handshakeTimeout))

	pub := s.Conn().RemotePublicKey()
	if pub == nil {
		// Unsecured connections cannot prove ownership.
		_ = s.Reset()
		return
	}

	var req RegisterRequest
	if err := readJSON(s, &req); err != nil {
		log.Printf("aliasresolver: register decode from %s: %v", s.Conn().RemotePeer(), err)
		_ = s.Reset()
		return
	}

	if req.ID == "" || len(req.Sig) == 0 {
		_ = s.Reset()
		return
	}

	ok, err := pub.Verify([]byte(req.ID), req.Sig)
	if err != nil || !ok {
		log.Printf("aliasresolver: register sig invalid from %s", s.Conn().RemotePeer())
		_ = s.Reset()
		return
	}

	remote := s.Conn().RemotePeer()

	r.mu.Lock()
	if e, exists := r.table[req.ID]; exists && !e.Owner.Equals(pub) {
		r.mu.Unlock()
		log.Printf("aliasresolver: register conflict for id from %s", remote)
		_ = s.Reset()
		return
	}
	r.table[req.ID] = Entry{Peer: remote, Owner: pub}
	r.mu.Unlock()

	_ = writeStatus(s, statusOK)
}

// HandleResolve looks up the listener for the requested WarpID, opens
// an upstream StopProtocol stream to it, acknowledges the dialer, then
// pipes bytes both ways until either side closes.
func (r *Resolver) HandleResolve(s network.Stream) {
	_ = s.SetDeadline(time.Now().Add(handshakeTimeout))

	br := bufio.NewReader(s)
	var req ResolveRequest
	if err := readJSONFrom(br, &req); err != nil {
		log.Printf("aliasresolver: resolve decode from %s: %v", s.Conn().RemotePeer(), err)
		_ = s.Reset()
		return
	}

	if req.ID == "" {
		_ = s.Reset()
		return
	}

	r.mu.RLock()
	e, ok := r.table[req.ID]
	r.mu.RUnlock()
	if !ok {
		_ = s.Reset()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	upstream, err := r.host.NewStream(ctx, e.Peer, StopProtocol)
	cancel()
	if err != nil {
		log.Printf("aliasresolver: open stop stream to %s: %v", e.Peer, err)
		_ = s.Reset()
		return
	}

	if err := writeStatus(s, statusOK); err != nil {
		_ = s.Reset()
		_ = upstream.Reset()
		return
	}

	// Clear the deadline so the long-lived data flow is not bounded by
	// the handshake budget.
	_ = s.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	pipe(br, s, upstream)
}

// pipe shuffles bytes between dialer (downBuf wrapping down) and upstream.
// Reads from the dialer come from the buffered reader so any bytes
// accidentally pulled into the buffer during the JSON parse are not lost.
func pipe(downBuf io.Reader, down, up network.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, downBuf)
		_ = up.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(down, up)
		_ = down.CloseWrite()
	}()
	wg.Wait()
	_ = down.Close()
	_ = up.Close()
}

// readJSON reads one newline-delimited JSON value from r. We use a
// line-delimited framing rather than json.Decoder directly because the
// decoder's internal buffering can swallow bytes that belong to a
// subsequent piping phase.
func readJSON(r io.Reader, v any) error {
	br := bufio.NewReader(io.LimitReader(r, maxFrameSize))
	return readJSONFrom(br, v)
}

func readJSONFrom(br *bufio.Reader, v any) error {
	line, err := br.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(line) == 0 {
		return io.ErrUnexpectedEOF
	}
	return json.Unmarshal(line, v)
}

// writeStatus sends a single newline-terminated status line.
func writeStatus(w io.Writer, status string) error {
	_, err := w.Write([]byte(status + "\n"))
	return err
}

// WriteJSON is exported for use by client packages that share the wire
// framing (line-delimited JSON).
func WriteJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// ReadStatus reads one line and returns it without the trailing newline.
// Errors are surfaced verbatim.
func ReadStatus(r *bufio.Reader) (string, error) {
	line, err := r.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
	}
	return string(line), nil
}
