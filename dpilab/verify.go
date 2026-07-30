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

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// A flow as ndpiReader serializes it with `-K json -k <file>`: one JSON object
// per line. Only the fields the verdict needs are decoded.
type ndpiFlow struct {
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dest_ip"`
	SrcPort int    `json:"src_port"`
	DstPort int    `json:"dst_port"`
	L4      string `json:"proto"`
	Xfer    struct {
		Src2DstBytes int64 `json:"src2dst_bytes"`
		Dst2SrcBytes int64 `json:"dst2src_bytes"`
	} `json:"xfer"`
	TCPFlags struct {
		Src2DstSyn int `json:"src2dst_syn_count"`
	} `json:"tcp_flags"`
	NDPI struct {
		Proto      string            `json:"proto"`
		ProtoID    string            `json:"proto_id"`
		Category   string            `json:"category"`
		Breed      string            `json:"breed"`
		Encrypted  int               `json:"encrypted"`
		Hostname   string            `json:"hostname"`
		Confidence map[string]string `json:"confidence"`
		FlowRisk   map[string]struct {
			Risk     string `json:"risk"`
			Severity string `json:"severity"`
		} `json:"flow_risk"`
		TLS map[string]any `json:"tls"`
	} `json:"ndpi"`
}

// Risks that mean a DPI box can tell this traffic from browsing: either it says
// outright that the flow is obfuscated, or it says the TLS is not the TLS a
// browser produces. Any one of them fails the camouflage arm.
var tellRisks = map[string]string{
	"56": "nDPI flagged the flow as obfuscated traffic",
	"15": "nDPI decided this TLS is not carrying HTTPS",
	"35": "payload entropy does not look like TLS records",
	"17": "malformed packets - the camouflage produced invalid TLS",
	"24": "no SNI: browsers always send one",
	"52": "ALPN does not match the SNI",
	"31": "uncommon TLS ALPN for a browser",
	"33": "suspicious TLS extension",
	"34": "TLS fatal alert - the handshake was rejected",
	"6":  "self-signed certificate",
	"10": "certificate does not match the SNI",
	"32": "certificate validity too long for a public CA",
	"9":  "certificate expired",
	"41": "certificate about to expire",
	"7":  "obsolete TLS version",
	"8":  "weak TLS cipher",
	"16": "SNI looks machine-generated (DGA)",
	"12": "numeric SNI",
	"28": "malicious fingerprint",
	"29": "malicious certificate fingerprint",
	"55": "nDPI flagged the flow as a probing attempt",
	"39": "non-printable characters where a protocol expects text",
}

// Risks that say something about how the lab is deployed rather than about the
// camouflage, so they are reported and not fatal. Every entry needs a reason.
var deploymentRisks = map[string]string{
	// Warpnet relays listen on 4001, and TLS off 443 is flagged by design.
	// This is a property of the port, not of the transport: re-run with
	// PORT=443 and it disappears.
	"5": "TLS on a non-standard port (relay port, not a transport artifact)",
	// There is no DNS in the lab, so the SNI can never resolve to the peer.
	"51": "SNI does not resolve (the lab has no DNS)",
	// Both are timing observations about a synthetic traffic pattern.
	"48": "periodic flow (the lab dials on a fixed interval)",
	"50": "TCP connection issues (teardown races the end of the capture)",
	"49": "minor issues",
	"46": "unidirectional traffic (flow cut off by the end of the capture)",
}

// browserLabels are the client names nDPI prints when its fingerprint database
// recognises the TLS client as a browser. They only appear in the verbose text
// output, not in the JSON, so the log is read separately.
var browserLabels = []string{"[Chrome]", "[Firefox]", "[Safari]", "[Microsoft Edge]", "[Edge]", "[Opera]"}

type verdict struct {
	flows []ndpiFlow
	fails []string
	notes []string
}

func runVerify(path, ndpiLog, wireA, wireB string, port, minFlows, minHandshakes int, expect string) error {
	flows, err := loadFlows(path)
	if err != nil {
		return err
	}

	v := &verdict{}
	for _, f := range flows {
		if !onLabWire(f, wireA, wireB, port) {
			continue
		}
		v.flows = append(v.flows, f)
	}

	fmt.Printf("\n%d of %d flows in %s are lab traffic (%s <-> %s port %d)\n",
		len(v.flows), len(flows), path, wireA, wireB, port)
	for i, f := range v.flows {
		fmt.Printf("  flow %d  %s:%d -> %s:%d  %s  proto=%s confidence=%s category=%s\n",
			i+1, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.L4,
			nonEmpty(f.NDPI.Proto), confidenceOf(f), nonEmpty(f.NDPI.Category))
		fmt.Printf("            bytes=%d/%d syns=%d sni=%q %s\n",
			f.Xfer.Src2DstBytes, f.Xfer.Dst2SrcBytes, f.TCPFlags.Src2DstSyn, f.NDPI.Hostname, tlsSummary(f))
		fmt.Printf("            risks: %s\n", risksOf(f))
	}

	v.check(len(v.flows) >= minFlows,
		fmt.Sprintf("expected at least %d lab flows in the capture, got %d", minFlows, len(v.flows)))

	// The transport dials from its own listen port, so every relay-to-relay
	// connection shares one 5-tuple and ndpiReader keys flows by tuple: all the
	// rounds land in a single flow. Count the SYNs instead, so a lab that only
	// managed one handshake cannot pass as one that survived all of them.
	handshakes := 0
	for _, f := range v.flows {
		handshakes += f.TCPFlags.Src2DstSyn
	}
	v.check(handshakes >= minHandshakes,
		fmt.Sprintf("expected at least %d handshakes on the lab wire, counted %d SYNs", minHandshakes, handshakes))

	for i, f := range v.flows {
		tag := fmt.Sprintf("flow %d (%s:%d -> %s:%d)", i+1, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)

		master := masterProto(f)
		v.check(master == "TLS", fmt.Sprintf("%s: nDPI called it %s, browsing is TLS", tag, nonEmpty(f.NDPI.Proto)))
		v.check(strings.Contains(confidenceOf(f), "DPI"),
			fmt.Sprintf("%s: classified as %s by %s, not by DPI", tag, f.NDPI.Proto, confidenceOf(f)))

		for id, r := range f.NDPI.FlowRisk {
			switch {
			case tellRisks[id] != "":
				v.check(false, fmt.Sprintf("%s: risk %s %q - %s", tag, id, r.Risk, tellRisks[id]))
			case deploymentRisks[id] != "":
				v.note(fmt.Sprintf("%s: risk %s %q allowed - %s", tag, id, r.Risk, deploymentRisks[id]))
			default:
				// An unclassified risk is a distinguisher nobody has looked
				// at yet, so it fails until it is triaged into one of the
				// two tables above.
				v.check(false, fmt.Sprintf("%s: untriaged risk %s %q", tag, id, r.Risk))
			}
		}
	}

	if ndpiLog != "" {
		label, err := browserLabel(ndpiLog, wireA, wireB)
		if err != nil {
			return err
		}
		v.check(label != "",
			"nDPI's fingerprint database did not recognise the TLS client as a browser")
		if label != "" {
			fmt.Printf("\nnDPI identified the client as %s from its TLS fingerprint\n", label)
		}
	}

	return v.report(expect)
}

func (v *verdict) check(ok bool, failure string) {
	if !ok {
		v.fails = append(v.fails, failure)
	}
}

func (v *verdict) note(s string) { v.notes = append(v.notes, s) }

// report turns the findings into an exit status. The camouflage arm has to look
// like browsing; the control arm has to *not* look like browsing, otherwise the
// checks above are not measuring anything.
func (v *verdict) report(expect string) error {
	sort.Strings(v.fails)

	if len(v.notes) > 0 {
		fmt.Printf("\nallowed (deployment, not camouflage):\n")
		for _, n := range v.notes {
			fmt.Printf("  - %s\n", n)
		}
	}
	if len(v.fails) > 0 {
		fmt.Printf("\ndistinguishers found:\n")
		for _, f := range v.fails {
			fmt.Printf("  - %s\n", f)
		}
	}

	switch expect {
	case "browsing":
		if len(v.fails) > 0 {
			return fmt.Errorf("VERDICT: DISTINGUISHABLE - %d finding(s)", len(v.fails))
		}
		fmt.Printf("\nVERDICT: INDISTINGUISHABLE FROM BROWSING - %d flows classified as TLS by DPI, no telltale risks\n", len(v.flows))
		return nil
	case "not-browsing":
		if len(v.fails) == 0 {
			return fmt.Errorf(
				"VERDICT: control arm also looks like browsing - the checks cannot tell camouflaged " +
					"traffic from plain libp2p, so a green camouflage arm proves nothing")
		}
		fmt.Printf("\nVERDICT: CONTROL ARM IS DISTINGUISHABLE as expected - %d finding(s), the checks do bite\n", len(v.fails))
		return nil
	default:
		return fmt.Errorf("unknown -expect %q", expect)
	}
}

// browserLabel returns the browser nDPI put on the lab flow, or "" if it put
// none on it.
func browserLabel(logPath, wireA, wireB string) (string, error) {
	body, err := os.ReadFile(logPath)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.Contains(line, wireA) || !strings.Contains(line, wireB) {
			continue
		}
		for _, label := range browserLabels {
			if strings.Contains(line, label) {
				return strings.Trim(label, "[]"), nil
			}
		}
	}
	return "", nil
}

func loadFlows(path string) ([]ndpiFlow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var flows []ndpiFlow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var fl ndpiFlow
		if err := json.Unmarshal([]byte(line), &fl); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		flows = append(flows, fl)
	}
	return flows, sc.Err()
}

func onLabWire(f ndpiFlow, wireA, wireB string, port int) bool {
	if f.L4 != "TCP" {
		return false
	}
	if f.SrcPort != port && f.DstPort != port {
		return false
	}
	pair := (f.SrcIP == wireA && f.DstIP == wireB) || (f.SrcIP == wireB && f.DstIP == wireA)
	return pair
}

func masterProto(f ndpiFlow) string {
	return strings.SplitN(f.NDPI.Proto, ".", 2)[0]
}

func confidenceOf(f ndpiFlow) string {
	if len(f.NDPI.Confidence) == 0 {
		return "none"
	}
	out := make([]string, 0, len(f.NDPI.Confidence))
	for _, v := range f.NDPI.Confidence {
		out = append(out, v)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func risksOf(f ndpiFlow) string {
	if len(f.NDPI.FlowRisk) == 0 {
		return "none"
	}
	ids := make([]string, 0, len(f.NDPI.FlowRisk))
	for id := range f.NDPI.FlowRisk {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, fmt.Sprintf("%s/%s", id, f.NDPI.FlowRisk[id].Risk))
	}
	return strings.Join(out, ", ")
}

// tlsSummary prints whatever ndpiReader managed to extract from the handshake -
// the fingerprint a DPI box would compare against a browser.
func tlsSummary(f ndpiFlow) string {
	keys := []string{"version", "negotiated_alpn", "advertised_alpns", "ja3s", "ja4", "cipher", "subjectDN"}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		v, ok := f.NDPI.TLS[k]
		if !ok {
			continue
		}
		s := fmt.Sprintf("%v", v)
		if s == "" || s == "0" {
			continue
		}
		if len(s) > 60 {
			s = s[:57] + "..."
		}
		out = append(out, fmt.Sprintf("%s=%s", k, s))
	}
	if len(out) == 0 {
		return "tls: (nothing extracted)"
	}
	return strings.Join(out, " ")
}

func nonEmpty(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
