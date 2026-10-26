"""5G-AKA (3GPP TS 33.501, section 6.1.3.2 and Annex A).

AKA is how the phone and the network prove to each other that they're
real, and agree on keys for the session. Three parties are involved:

    UE      the phone and its SIM (USIM). Knows K and OPc.
    SEAF    the network the phone is connected to right now. This can be
            a different operator if you're roaming abroad.
    AUSF    the home network's authentication server. It works together
            with the UDM/ARPF, which stores K and OPc for every customer.

What happens:
    1. The UDM makes an auth vector: RAND, AUTN, XRES* and KAUSF
    2. The AUSF keeps XRES* and KAUSF for itself. The SEAF only gets
       RAND, AUTN and HXRES*, which is a hash of XRES*. So a dodgy
       roaming network never learns the real expected answer.
    3. The phone checks AUTN ("is this really my home network, and is
       this a new message?") and answers with RES*
    4. The SEAF hashes RES* and compares it to HXRES*, a quick local check
    5. The AUSF compares RES* to XRES*. That's the real decision. Only
       if it matches does the SEAF get the key KSEAF.

The main upgrade from 4G: the serving network's name is mixed into the
keys and into RES*, so one network can't pretend to be another one.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from hashlib import sha256

from .milenage import Milenage, xor

# AMF = Authentication Management Field. The top bit is the "separation
# bit", and it has to be 1 for 4G/5G. That stops a vector made for old 3G
# from being used here.
DEFAULT_AMF = bytes.fromhex("8000")

# Function codes for the KDF (TS 33.501 Annex A). Each key type gets its
# own code, so you can't trick the KDF into giving you one key in place of
# another.
FC_KAUSF = 0x6A
FC_RES_STAR = 0x6B
FC_KSEAF = 0x6C


class AuthError(Exception):
    """Authentication failed.

    `cause` is a short code like "MAC_FAILURE" so the code (and the logs)
    can tell exactly why it failed, not just that it failed.
    """

    def __init__(self, cause: str, message: str) -> None:
        super().__init__(message)
        self.cause = cause


def serving_network_name(mcc: str, mnc: str) -> bytes:
    """Build the serving network name, e.g. 5G:mnc001.mcc242.3gppnetwork.org

    MCC is the country code (242 = Norway), MNC is the operator code.
    MNC is always written with 3 digits, so "01" becomes "001".
    """
    return f"5G:mnc{mnc.zfill(3)}.mcc{mcc}.3gppnetwork.org".encode()


def kdf(key: bytes, fc: int, *params: bytes) -> bytes:
    """The generic 3GPP key derivation function (TS 33.220 Annex B.2).

    It's HMAC-SHA-256 over:  FC || P0 || L0 || P1 || L1 || ...
    where each Ln is the length of Pn as 2 bytes.

    Putting the length after every parameter means you can't shift bytes
    from one parameter to the next and get the same input.
    """
    s = bytes([fc])
    for p in params:
        s += p + len(p).to_bytes(2, "big")
    return hmac.new(key, s, sha256).digest()


def res_star(ck: bytes, ik: bytes, snn: bytes, rand: bytes, res: bytes) -> bytes:
    """RES* = the 5G version of RES. Ties the answer to this network name."""
    # The KDF gives 32 bytes, the spec keeps the last 16
    return kdf(ck + ik, FC_RES_STAR, snn, rand, res)[16:]


def hres_star(rand: bytes, res_star_value: bytes) -> bytes:
    """Hash of RES*. This is what the serving network gets to check against."""
    return sha256(rand + res_star_value).digest()[16:]


# ---------------------------------------------------------------------------
# Home network
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HomeAuthVector:
    """Everything the home network makes. It keeps all of this."""
    rand: bytes
    autn: bytes
    xres_star: bytes   # the answer we expect from the phone
    kausf: bytes       # top-level key, never leaves the home network


@dataclass(frozen=True)
class ServingAuthVector:
    """The reduced version that goes to the serving network.

    Notice there's no xres_star or kausf here. That's on purpose.
    """
    rand: bytes
    autn: bytes
    hxres_star: bytes


def generate_auth_vector(mil: Milenage, sqn: bytes, snn: bytes,
                         amf: bytes = DEFAULT_AMF,
                         rand: bytes | None = None) -> HomeAuthVector:
    """UDM/ARPF: make an auth vector for one login attempt.

    rand can be set by the tests. Otherwise it's random, which it has to
    be in real use, or old answers could be replayed.
    """
    rand = rand or os.urandom(16)

    # Run all the MILENAGE functions at once
    out = mil.compute_all(rand, sqn, amf)

    # SQN goes up by one every login. If it was sent in clear text,
    # someone could follow a phone by watching the counter. XOR with AK
    # hides it, and only someone with K can calculate AK.
    sqn_xor_ak = xor(sqn, out.ak)

    # AUTN = hidden SQN (6) || AMF (2) || MAC (8) = 16 bytes
    autn = sqn_xor_ak + amf + out.mac_a

    return HomeAuthVector(
        rand=rand,
        autn=autn,
        xres_star=res_star(out.ck, out.ik, snn, rand, out.res),
        kausf=kdf(out.ck + out.ik, FC_KAUSF, snn, sqn_xor_ak),
    )


def to_serving_vector(av: HomeAuthVector) -> ServingAuthVector:
    """Strip the secrets out before handing the vector to the serving network."""
    return ServingAuthVector(av.rand, av.autn, hres_star(av.rand, av.xres_star))


def derive_kseaf(kausf: bytes, snn: bytes) -> bytes:
    """KSEAF = the key the serving network gets. Bound to its name."""
    return kdf(kausf, FC_KSEAF, snn)


# ---------------------------------------------------------------------------
# Phone / SIM
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UEResult:
    """What the phone ends up with after a successful check."""
    res_star: bytes   # sent back to the network
    kausf: bytes      # kept on the phone
    kseaf: bytes      # kept on the phone
    sqn: int          # the new highest SQN, so the next one has to be bigger


def ue_authenticate(mil: Milenage, rand: bytes, autn: bytes, snn: bytes,
                    highest_sqn: int) -> UEResult:
    """What the SIM does when the network sends RAND and AUTN.

    highest_sqn is the biggest SQN this SIM has accepted before.
    Raises AuthError if anything is off.
    """
    if len(rand) != 16 or len(autn) != 16:
        raise AuthError("MALFORMED", "RAND and AUTN must be 16 bytes")

    # Split AUTN into its three parts
    sqn_xor_ak, amf, mac = autn[:6], autn[6:8], autn[8:]

    # Get SQN back. We calculate the same AK the network used, and since
    # XOR twice with the same value cancels out, we're left with SQN.
    res, ak = mil.f2_f5(rand)
    sqn = xor(sqn_xor_ak, ak)

    # Check 1: is this really my home network?
    # Only someone who knows K can make the right MAC. A fake base
    # station doesn't have K, so it gets stopped here.
    if not hmac.compare_digest(mil.f1(rand, sqn, amf), mac):
        raise AuthError("MAC_FAILURE", "network authentication failed")

    # Check 2: is this a new message?
    # An attacker could record a real RAND/AUTN and send it again later.
    # The MAC would still be valid, but the SQN would be old, so it's
    # caught here.
    sqn_int = int.from_bytes(sqn, "big")
    if sqn_int <= highest_sqn:
        raise AuthError("SYNCH_FAILURE", "SQN not fresh, possible replay")

    # Check 3: was this vector actually made for 4G/5G?
    if not amf[0] & 0x80:
        raise AuthError("AMF_SEPARATION", "AMF separation bit not set")

    # All good. Calculate the keys the same way the home network did.
    ck, ik = mil.f3(rand), mil.f4(rand)
    kausf = kdf(ck + ik, FC_KAUSF, snn, sqn_xor_ak)
    return UEResult(
        res_star=res_star(ck, ik, snn, rand, res),
        kausf=kausf,
        kseaf=derive_kseaf(kausf, snn),
        sqn=sqn_int,
    )


# ---------------------------------------------------------------------------
# Network side checks
# ---------------------------------------------------------------------------
#
# Every comparison below uses hmac.compare_digest instead of ==. The normal
# == stops at the first byte that's different, so in theory an attacker
# could time it and guess the right answer one byte at a time.
# compare_digest always takes the same amount of time.

def seaf_check(sv: ServingAuthVector, res_star_value: bytes) -> bool:
    """Serving network: hash the phone's answer and compare with HXRES*."""
    return hmac.compare_digest(hres_star(sv.rand, res_star_value), sv.hxres_star)


def ausf_confirm(av: HomeAuthVector, res_star_value: bytes, snn: bytes) -> bytes:
    """Home network: the final check. Gives out KSEAF only if it matches."""
    if not hmac.compare_digest(res_star_value, av.xres_star):
        raise AuthError("RES_MISMATCH", "RES* does not match XRES*")
    return derive_kseaf(av.kausf, snn)
