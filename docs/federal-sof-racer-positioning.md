# Federal SOF-RACER Positioning

Status: opportunity positioning only. This document is not a procurement claim,
award claim, compliance claim, or supported federal deployment statement.

## Public Context

Public SOF AT&L materials describe a Commercial Solutions Opening (CSO) that
remains open for two years and is refined through specific calls. The SAM.gov
notice says interested vendors may submit only in response to a specific call.
It also describes SOF-RACER as a consortium-manager structure for prototype
projects.

The public SOF-RACER site lists AOI VI, Multi-Domain Communications & Cyber
Operations, for resilient communications, cyber defense, and edge computing in
contested or disconnected environments. USSOCOM's public capability areas also
include Protected, Congested, Contested Communications; Mobility Communications;
Cyberspace Operations; and Information Assurance.

Public references:

- USSOCOM SOF AT&L CSO on SAM.gov:
  <https://sam.gov/opp/d301463c1df546af9ffd4c910a1428ca/view>
- SOF-RACER public AOI page:
  <https://www.sof-racer.com/>
- USSOCOM capability areas of interest:
  <https://www.socom.mil/SOF-ATL/Pages/capability_AOI.aspx>

## FreeQ Fit

FreeQ's relevant lane is protected overlay networking for routable digital
traffic between trusted nodes.

FreeQ can operate in two connectivity patterns:

```text
direct node-to-node:
Node A -> FreeQ protected overlay -> Node B
```

```text
gateway/rendezvous assisted:
Node A -> FreeQ protected overlay -> reachable gateway/rendezvous -> FreeQ protected overlay -> Node B
```

This maps to environments where endpoints may be online but not directly
reachable because of NAT, CGNAT, Starlink, cellular, hotel Wi-Fi, airport Wi-Fi,
coalition networks, enterprise guest networks, or restrictive firewalls.

## Accurate Claim

Use:

```text
FreeQ protects routable digital traffic moving between trusted nodes across
whatever bearer is available: public internet, fiber, LTE, SATCOM, Starlink,
Wi-Fi, tactical backhaul, or private network. When direct node-to-node
connectivity is available, FreeQ can use it. When direct reachability is
blocked, FreeQ can use a reachable gateway or rendezvous point.
```

Do not use:

```text
FreeQ replaces tactical radios, SATCOM, Link 16, Type 1 encryption, approved
COMSEC, or radio-layer security.
```

Do not claim:

- SOF-RACER award, membership, endorsement, or procurement eligibility.
- federal accreditation or authorization to operate.
- classified, Type 1, or COMSEC replacement capability.
- arbitrary RF waveform protection.
- Linux or gateway hardware support before the acceptance gates pass.

## Demo Story

The strongest near-term demo lane is:

```text
operator laptop on restricted network
    -> FreeQ protected overlay
        -> reachable gateway/rendezvous
            -> trusted cloud, partner node, or command-side system
```

The demo should show:

- setup and identity bootstrap
- `freeq gateway status`
- `freeq gateway`
- `freeq status`
- bidirectional smoke evidence where available
- `freeq stop` rollback

## Release Gate

This positioning becomes stronger only after the relevant platform gates pass:

- macOS field flow remains working and rollback-safe.
- Linux support remains preflight-only until
  `docs/linux-supported-acceptance.md` passes.
- production gateway/server support must have real-host service, rollback,
  upgrade, and uninstall evidence.

