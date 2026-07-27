# Legacy Gateway Field Test Lessons

Status: legacy learning, not the target product architecture

The first AWS gateway field-test path is archived as a learning artifact. It
proved useful engineering facts, but it is not the shape FreeQ should present to
users or operators.

## What Worked

- A public gateway can accept outbound sessions from leaves behind restricted
  networks.
- A leaf-to-gateway overlay can pass packets when the local network allows the
  AWS endpoint.
- End-to-end opaque relay mode can carry leaf-to-leaf traffic when both leaves
  have the same relay key and both outbound sessions are healthy.
- The gateway must forward over active leaf sessions. It must not depend on
  dialing back into CGNAT, hotel Wi-Fi, Starlink, LTE, or guest-network leaves.

## What Failed As A Product Flow

The field-test path required too much manual state:

- manual relay key generation and copy/paste
- manual `FREEQ_EXTRA_ALLOWED_IPS`
- manual restart timing across multiple machines
- manual interpretation of route tables, logs, API counters, and ping output
- manual AWS gateway checks
- manual distinction between daemon process state and real network health

That is not acceptable for FreeQ.

The phrase "FreeQ daemon is running" is not a health result. A daemon can be
alive while the gateway is unreachable, the relay key is wrong, the route is
missing, the TUN device is not observing packets, or the remote leaf is offline.

## Concrete Failure Modes Observed

- One side connected while the other side did not.
- Gateway reachability changed depending on the local network.
- TCP reachability to the gateway could fail before FreeQ had any chance to
  establish a UDP session.
- The local API reported process state while the tunnel was not usable.
- Packet counters did not clearly identify whether the problem was route
  installation, TUN observation, session establishment, relay forwarding, or
  decrypt failure.
- Stale peer sessions could remain in daemon state and mislead later transmit
  attempts.
- The operator had to infer too much from raw logs.

## Archive Decision

The legacy gateway flow remains useful as a lab artifact and regression source,
but it must not drive new product decisions. The replacement architecture is the
self-healing network manager described in
[`docs/self-healing-network-redesign.md`](self-healing-network-redesign.md).

Future development should use this document only for failure examples and test
fixtures. Do not rebuild the product around this manual workflow.
