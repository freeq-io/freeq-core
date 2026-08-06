# Gateway Path Field Results 2026-08-05

This note captures the two field runs collected on August 5, 2026 for the
Patrick to David gateway relay path. The raw evidence bundles remain under
`~/FreeQ/03-perf-results/`, and this file records the part we want preserved in
the repo.

## What the runs showed

- FreeQ leaf-to-leaf relay through the AWS gateway worked end to end.
- Overlay RTT from Patrick to David through the gateway landed around 108 to
  119 ms average, with 0% packet loss across 50 packet probes in both runs.
- UDP throughput held cleanly at 0.5, 1, 2, and 4 Mbps with 0% reported loss
  in the August 5 runs.
- TCP bulk also completed in these runs, around 2.55 to 3.08 Mbps.

## Run comparison

| Label | Gateway public host probe | Gateway overlay probe | Remote overlay RTT avg | UDP ladder | TCP bulk |
|------|----------------------------|-----------------------|------------------------|-----------|----------|
| `patrick-to-david-gateway-20260805T203648Z` | 100% loss | 100% loss | 119.25 ms | 0.5M to 4M all passed | 2.55 Mbps |
| `patrick-to-david-gateway-20260805T204617Z` | not collected | not collected | 108.24 ms | 0.5M to 4M all passed | 3.08 Mbps |

## Interpretation

The first run is the interesting one because it proves something operationally
useful: the gateway itself did not answer ICMP on either its public host or its
overlay IP, but the relay path still carried end-to-end traffic between the two
leaves successfully. That means a failed direct ping to the gateway should not
be treated as proof that relay forwarding is broken.

The second run removed the extra gateway probe inputs and focused on the
end-to-end relay path. That produced the cleaner publishable result:
leaf-to-leaf RTT stayed just over 108 ms average with no packet loss, UDP held
steady through 4 Mbps, and TCP also moved successfully.

## What we should say externally

- Two outbound-only leaves exchanged traffic through an AWS FreeQ gateway.
- The gateway did not need to dial either leaf.
- End-to-end overlay latency was about 108 to 119 ms in this field test.
- UDP relay samples were clean through 4 Mbps in this run set.
- This is field evidence for relay viability, not a blanket claim about all
  traffic profiles, all networks, or complete zero-trust capability.

## Follow-up

- Keep using the relay path result as the primary success criterion.
- Treat gateway ICMP response as optional evidence only.
- Use the improved report generator so future `RESULTS.md` output explains this
  distinction automatically.
