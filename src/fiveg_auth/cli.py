"""Command line tool: `5g-auth simulate [--attack ...]`.

Without --attack it just runs a normal login and prints each step.
With --attack it first does a normal login, then tries one attack and
shows which check stops it.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import aka
from .milenage import compute_opc
from .network import UE, HomeNetwork, ServingNetwork, Subscriber

# Terminal colour codes per party, so it's easier to see who does what
COLORS = {"UE": "36", "SEAF": "33", "AUSF": "35", "SIDF": "35", "ATTACK": "31"}


def log(actor: str, msg: str) -> None:
    """Print one line like '    UE | sending ...'."""
    color = COLORS.get(actor, "0")
    # Only use colours in a real terminal. If the output goes to a file
    # or CI log, the colour codes would just show up as junk.
    tag = f"\033[{color}m{actor:>6}\033[0m" if sys.stdout.isatty() else f"{actor:>6}"
    print(f"{tag} | {msg}")


def build_world(mcc: str = "242", mnc: str = "01"):
    """Set up one home network, one serving network and one phone.

    242 is Norway's country code. K and OP are random every run, which is
    fine since the phone and the network get the same values.
    """
    home = HomeNetwork(mcc, mnc, log=log)
    k, op = os.urandom(16), os.urandom(16)
    opc = compute_opc(k, op)

    # Register the customer in the home network, and give the phone the
    # same K/OPc plus the home network's public key (like a SIM card would)
    home.add_subscriber(Subscriber("0123456789", k, opc))
    ue = UE(mcc, mnc, "0123456789", k, opc, home.key.public_bytes, log=log)
    return home, ServingNetwork(mcc, mnc, home, log=log), ue


def run(attack: str | None) -> int:
    """Run the simulation. Returns 0 if things went as expected, 1 if not."""
    home, seaf, ue = build_world()
    print(f"Subscriber {ue.supi}\n")

    # Always do one normal login first, to show the happy path
    seaf.register(ue)
    if attack is None:
        return 0

    print()
    try:
        if attack == "replay":
            # Attacker records a real challenge and sends it to the phone
            # again. The first time is fine, the second has an old SQN.
            log("ATTACK", "capturing a challenge and replaying it to the UE")
            s = ue.make_suci()
            sv = home.authenticate(s, seaf.snn)
            ue.on_auth_request(sv.rand, sv.autn, seaf.snn)      # the real one
            ue.on_auth_request(sv.rand, sv.autn, seaf.snn)      # the replay

        elif attack == "fake-network":
            # A fake base station doesn't know K, so the best it can do is
            # send random bytes. The MAC check catches it.
            log("ATTACK", "fake base station without K sends a forged AUTN")
            ue.on_auth_request(os.urandom(16), os.urandom(16), seaf.snn)

        elif attack == "tamper-suci":
            # Flip one bit in the encrypted part of the SUCI (byte 35 is
            # just past the 33-byte public key). The HMAC tag catches it.
            log("ATTACK", "flipping one bit in the SUCI ciphertext")
            s = ue.make_suci()
            s.output = s.output[:35] + bytes([s.output[35] ^ 1]) + s.output[36:]
            home.authenticate(s, seaf.snn)

        elif attack == "wrong-network":
            # A rogue network takes a challenge that was made for another
            # network and tries to use it under its own name. RES* is tied
            # to the network name, so the home network rejects it.
            log("ATTACK", "rogue network reuses a vector made for another SNN")
            sv = home.authenticate(ue.make_suci(), seaf.snn)
            other = aka.serving_network_name("999", "99")
            res = ue.on_auth_request(sv.rand, sv.autn, other)
            home.confirm(sv.rand, res)

    except aka.AuthError as e:
        # This is what we want: the attack was stopped, and we print why
        log("ATTACK", f"blocked: {e.cause} ({e})")
        return 0

    # If we get here, no check fired, which would be a bug
    log("ATTACK", "NOT blocked")
    return 1


def main(argv: list[str] | None = None) -> int:
    """Read the command line arguments and start the simulation."""
    p = argparse.ArgumentParser(prog="5g-auth", description="5G authentication toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)
    sim = sub.add_parser("simulate", help="run a 5G registration")
    sim.add_argument("--attack", choices=["replay", "fake-network", "tamper-suci", "wrong-network"])
    args = p.parse_args(argv)
    return run(args.attack)


if __name__ == "__main__":
    raise SystemExit(main())
