# dpilab — is the camouflaged traffic distinguishable from browsing?

Runs two libp2p relay nodes over the camouflage transport across a sniffable
wire, captures the wire, and asks [nDPI](https://github.com/ntop/nDPI) what it
just saw. No `sudo`: the whole lab lives in the network namespace of one
privileged container, and `--network none` keeps it off every real network.

```sh
./dpilab/run.sh                                  # build image + both arms, relays on 443
ARMS=camouflage ./dpilab/run.sh                  # skip the control arm
PORT=4001 ./dpilab/run.sh                        # production relay port instead of 443
SNI=10.77.0.11 ARMS=camouflage ./dpilab/run.sh   # break the SNI, watch it go red
OUT=/tmp/dpilab ./dpilab/run.sh                  # keep the pcaps and nDPI output
./dpilab/run.sh --shell                          # shell in the lab, run lab.sh by hand
```

The harness is behind the `dpilab` build tag, so it stays out of `go build ./...`;
the image builds it with `go build -tags dpilab ./dpilab`. `.github/workflows/labs.yml`
runs it on every push, on 443, and uploads the captures and nDPI output as an
artifact.

nDPI is built from source (pinned to tag `5.0` in the Dockerfile) because no
distro ships `ndpiReader` and the risk names the verdict matches on are only
stable within a release.

## Topology

```
root ns of the container
  bridge wire
  ├── br-a  <->  [ns dpi-a] eth-a 10.77.0.11   relay A: listens, answers
  └── br-b  <->  [ns dpi-b] eth-b 10.77.0.12   relay B: dials ROUNDS times
```

The capture runs on `br-a`, so every packet to and from relay A is recorded.
Both peers live in their own namespace on purpose: traffic between two IPs in
one namespace is delivered over loopback in 64 KB chunks, and segmentation
offload is switched off for the same reason. The transport splits its TLS
ClientHello across TCP segments, and a capture taken behind GSO would not show
the segments a DPI box actually sees. With offload off the capture tops out at
1448-byte segments, and the first ClientHello really does arrive as 136 + 1448 +
176 bytes.

Both nodes are relays — camouflage transport with its shipped defaults, Noise
inside it, a PSK, circuit v2 hop service, `ForceReachabilityPublic` — and B
takes a reservation on A, so the tunnel carries identify, ping, circuit v2 and
five 192 KB transfers rather than a bare handshake.

## What it asserts

nDPI runs with `-d`, so guessing by port and by IP is off and a TLS verdict can
only come from the payload; `-T 300` raises the per-flow packet budget above the
default 80 so the entropy and obfuscation heuristics see the bulk transfer too,
and `--tls_heuristics` turns on the TLS-in-TLS heuristics.

For the camouflage arm, every lab flow must:

- be classified `TLS` (master protocol), with `Confidence: DPI`;
- carry all `ROUNDS` handshakes (counted as SYNs, see below);
- be recognised as a **browser** by nDPI's own fingerprint database;
- raise no risk from the `tellRisks` table in `verify.go` — obfuscated traffic,
  "TLS not carrying HTTPS", suspicious entropy, malformed packets, missing SNI,
  ALPN/SNI mismatch, self-signed or mismatched certificate, DGA-looking SNI, and
  so on. Anything not in that table and not in the small `deploymentRisks`
  allowlist also fails, so a new nDPI risk cannot slip through untriaged.

For the control arm — the same libp2p stack on the stock TCP transport — the
same checks must **fail**. Without that arm a green run would prove nothing: an
empty capture passes every check that only looks for the absence of risks.

## Results

Camouflage arm, on 443:

```
proto=TLS.GoogleServices confidence=DPI category=Web
sni="www.googleapis.com" version=TLSv1.3 advertised_alpns=h2,http/1.1
tls_supported_versions=GREASE,TLSv1.3,TLSv1.2 ECH: version 0xfe0d
JA4: t13d1516h2_8daaf6152771_d8a2da3f94cd  ->  nDPI says: Chrome
risks: none
VERDICT: INDISTINGUISHABLE FROM BROWSING
```

Control arm, same wire, same traffic, stock TCP transport:

```
proto=Unknown confidence=none ClearText  tls: (nothing extracted)
VERDICT: CONTROL ARM IS DISTINGUISHABLE as expected
```

Notes on the run:

**1. On 443 there is not a single flow risk.** The one risk that does show up is
`Known Proto on Non Std Port`, and only when the relays run on the production
port: `PORT=4001 ./dpilab/run.sh`. It is a property of the port rather than of
the transport, which is why it sits in `deploymentRisks` instead of failing the
arm.

**2. nDPI names the client Chrome.** The uTLS `HelloChrome_Auto` fingerprint is
good enough that nDPI's fingerprint database labels the flow a browser, and it
extracts a plausible SNI, `h2,http/1.1` ALPN, TLS 1.3 with GREASE and even an
ECH extension. This label only appears in the verbose text output, not in the
JSON, so `verify` reads both.

**3. ClientHello fragmentation does not break the classification.** nDPI
reassembles the split ClientHello and still reports TLS. That is the desired
outcome here: the fragmentation is there to defeat single-segment signature
matching, not to make the flow unparsable, and an unparsable TLS flow would be
*more* suspicious, not less.

**4. All rounds land in one flow.** The transport dials from its own listen
port, so every relay-to-relay connection shares one 5-tuple, and `ndpiReader`
keys flows by tuple: five connections show up as one flow with five SYNs. The
verdict therefore requires `min-handshakes` SYNs instead of five separate flows,
so a lab that only managed one handshake cannot pass as one that survived all
five.

**5. The checks bite.** Besides the control arm, `SNI=10.77.0.11
ARMS=camouflage ./dpilab/run.sh` turns the arm red: uTLS omits the SNI extension
for an IP literal, and nDPI immediately raises `Missing SNI TLS Extn` and
`ALPN/SNI Mismatch`.

## What this does not prove

- **nDPI is not a censor.** It is a passive classifier. This lab says nothing
  about active probing, TLS-fingerprint allowlisting, or a middlebox that
  terminates the connection itself.
- **The SNI is not backed by DNS here.** nDPI reads a pcap and has no way to
  learn that `www.googleapis.com` does not resolve to the peer's address. A
  middlebox that sees the DNS traffic — or just holds a resolver — can compare
  the SNI against the destination IP, and that mismatch is a real distinguisher
  this lab cannot see.
- **The certificate is not validated.** nDPI parses the chain but does not
  check it against a trust store, so the fake "Cloudflare Inc ECC CA-3" leaf
  passes. Note it does not trip `Self-signed Cert` either, because the
  transport presents a two-certificate chain.
- **Traffic shape over time is out of scope.** Five dials over a couple of
  seconds is not a browsing session, and a long-lived relay connection has a
  timing profile no browser has. nDPI's `Periodic Flow` risk exists for exactly
  that and is currently allowlisted as a lab artifact.
