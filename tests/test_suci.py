"""Tests for SUCI Profile B against the official example in TS 33.501 Annex C.4.

The spec gives a fixed home network key, a fixed ephemeral key and the
exact output you should get. If my code gives the same bytes, it's
compatible with the standard.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from fiveg_auth import suci

h = bytes.fromhex

# Values from TS 33.501 Annex C.4 (Profile B)
HN_PRIV = h("F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA")
HN_PUB = h("0272DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD1")
EPH_PRIV = h("99798858A1DC6A2C68637149A4B1DBFD1FDFF5ADDD62A2142F06699ED7602529")
EPH_PUB = h("039AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1")
PLAINTEXT = h("00012080F6")   # MSIN 001002086 packed as BCD
CIPHERTEXT = h("46A33FC271")
MAC = h("6AC7DAE96AA30A4D")


@pytest.fixture
def hn():
    return suci.HomeNetworkKey.from_private_bytes(HN_PRIV)


def test_home_public_key(hn):
    """Public key calculated from the private key should match the spec."""
    assert hn.public_bytes == HN_PUB


def test_conceal_matches_spec_vector():
    """With the spec's ephemeral key, the output should be byte for byte the same."""
    eph = ec.derive_private_key(int.from_bytes(EPH_PRIV, "big"), suci.CURVE)
    assert suci.conceal(HN_PUB, PLAINTEXT, eph) == EPH_PUB + CIPHERTEXT + MAC


def test_deconceal_spec_vector(hn):
    """And the other way: the spec's SUCI should decrypt to the right ID."""
    assert hn.deconceal(EPH_PUB + CIPHERTEXT + MAC) == PLAINTEXT


def test_roundtrip_random(hn):
    """Encrypt and decrypt with a random ephemeral key, like in normal use."""
    out = suci.conceal(hn.public_bytes, b"\x10\x32\x54")
    assert hn.deconceal(out) == b"\x10\x32\x54"


def test_unlinkable(hn):
    """The same ID twice must give two different SUCIs.

    This is the whole privacy point of SUCI: a listener can't tell it's
    the same person.
    """
    a = suci.conceal(hn.public_bytes, PLAINTEXT)
    b = suci.conceal(hn.public_bytes, PLAINTEXT)
    assert a != b


@pytest.mark.parametrize("pos", [5, 34, -1])   # inside the public key, ciphertext and tag
def test_tampering_detected(hn, pos):
    """Flip one bit anywhere in the SUCI and it should be rejected."""
    out = bytearray(EPH_PUB + CIPHERTEXT + MAC)
    out[pos] ^= 0x01
    with pytest.raises(suci.SuciError):
        hn.deconceal(bytes(out))


def test_wrong_home_key_rejected():
    """A different home network can't decrypt someone else's SUCI."""
    other = suci.HomeNetworkKey.generate()
    with pytest.raises(suci.SuciError):
        other.deconceal(EPH_PUB + CIPHERTEXT + MAC)


def test_truncated_rejected(hn):
    """Too short to even contain a ciphertext."""
    with pytest.raises(suci.SuciError):
        hn.deconceal(EPH_PUB + MAC)


@pytest.mark.parametrize("msin,bcd", [("001002086", "00012080F6"), ("0123456789", "1032547698")])
def test_bcd(msin, bcd):
    """BCD packing both ways, with odd length (padded with F) and even length."""
    assert suci.msin_to_bcd(msin) == h(bcd)
    assert suci.bcd_to_msin(h(bcd)) == msin
