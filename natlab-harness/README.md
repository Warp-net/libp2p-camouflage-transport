# natlab — end-to-end NAT hole punch harness

Runs a real Warpnet hole punch between two peers sitting behind two independent
`MASQUERADE` NATs. No second machine and no `sudo`: the whole topology lives in
the network namespace of one privileged container, and `--network none` keeps it
off every real network, so it can never reach mainnet or testnet.

```sh
./deploy/natlab-harness/run.sh                  # build image + run the lab
FORCE_PRIVATE=1 ./deploy/natlab-harness/run.sh  # skip AutoNAT reachability probing
```

## Topology

```
root ns of the container = "the internet"
  bridge inet 11.0.0.0/24
  ├── relay          11.0.0.1     public: circuit relay + AutoNAT server + observer
  ├── [ns rtr-a] wan 11.0.0.11    MASQUERADE, lan 10.1.0.1/24
  │        └── [ns host-a] 10.1.0.2  peer A — dials B over the circuit
  └── [ns rtr-b] wan 11.0.0.12    MASQUERADE, lan 10.2.0.1/24
           └── [ns host-b] 10.2.0.2  peer B — accepts, drives DCUtR
```

Each router does port-preserving SNAT with no inbound port forwarding:
endpoint-independent mapping with address-dependent filtering — the NAT class
DCUtR is expected to traverse. Unsolicited inbound is dropped silently rather
than rejected, because a RST would abort the peer's dial instead of letting TCP
retransmit, and the retransmission is what makes a simultaneous open succeed.

The peers are built from the production `node.CommonOptions`, so the camouflage
transport, PSK, Noise, AutoNAT v2, AutoRelay and DCUtR are all the real thing.

## What it asserts

A green run is not "the peers connected" — the relay alone would satisfy that.
It requires all of:

- peer B holds a circuit reservation, and a plain TCP dial from host-a to
  `11.0.0.12:4001` **fails** while B is listening (proves the NAT is real);
- `EndHolePunch{Success:true}` from the DCUtR tracer on both sides;
- a connection that is neither `Limited` nor `/p2p-circuit`, whose remote
  address is the peer's **public** NAT address (proves the packets crossed the
  NAT instead of taking a LAN shortcut);
- a ping stream opened *without* `AllowLimitedConn`, so it physically cannot
  fall back to the relay, landing on that same connection.

## Note

 `observedaddrs.ActivationThresh = 2` does not block the punch.**
`HolePunchAddrs` deliberately asks for addresses with a single observer
(`addrs_manager.go:456`), so one relay is enough for candidates. The threshold
only gates the *advertised* address set. Worth noting that the three production
relays share one IP, and `getObserver` keys IPv4 observers by full address, so
all three count as a single observer for that threshold.
