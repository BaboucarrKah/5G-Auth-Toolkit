"""Tests for 5G-AKA and the full login flow.

The first half tests the AKA functions on their own. The second half
builds a whole little network (phone, serving network, home network) and
runs complete logins, including a few that should fail.
"""

import os

import pytest

from fiveg_auth import aka
from fiveg_auth.milenage import Milenage
from fiveg_auth.network import UE, HomeNetwork, ServingNetwork, Subscriber

h = bytes.fromhex

# K and OPc from TS 35.208 test set 1. Any 16-byte values would work here,
# but using known ones means MILENAGE itself is already proven correct.
K = h("465b5ce8b199b49faa5f0a2ee238a6bc")
OPC = h("cd63cb71954a9f4e48a5994e37a02baf")
SNN = aka.serving_network_name("242", "01")
SQN = (1).to_bytes(6, "big")


@pytest.fixture
def mil():
    return Milenage(K, OPC)


def test_serving_network_name():
    """MNC '01' should be padded to '001', like the spec says."""
    assert SNN == b"5G:mnc001.mcc242.3gppnetwork.org"


def test_kdf_encoding():
    """Build the KDF input by hand and check my kdf() gives the same result.

    Input should be FC || P0 || L0, where L0 is the length as 2 bytes.
    """
    import hashlib
    import hmac
    expected = hmac.new(b"k", b"\x6a" + b"abc" + b"\x00\x03", hashlib.sha256).digest()
    assert aka.kdf(b"k", 0x6A, b"abc") == expected


def test_full_aka(mil):
    """Normal login: every check passes and both sides end up with the same keys."""
    av = aka.generate_auth_vector(mil, SQN, SNN)    # home network makes a challenge
    sv = aka.to_serving_vector(av)                  # serving network gets the reduced one
    ue = aka.ue_authenticate(mil, sv.rand, sv.autn, SNN, highest_sqn=0)   # phone answers
    assert aka.seaf_check(sv, ue.res_star)                      # serving network is happy
    assert aka.ausf_confirm(av, ue.res_star, SNN) == ue.kseaf   # home network agrees, same key
    assert ue.kausf == av.kausf


def test_seaf_never_sees_xres_star(mil):
    """The serving network should never get the real expected answer or KAUSF."""
    sv = aka.to_serving_vector(aka.generate_auth_vector(mil, SQN, SNN))
    assert not hasattr(sv, "xres_star") and not hasattr(sv, "kausf")


def test_forged_autn(mil):
    """Fake base station without K: random AUTN must fail the MAC check."""
    with pytest.raises(aka.AuthError) as e:
        aka.ue_authenticate(mil, os.urandom(16), os.urandom(16), SNN, 0)
    assert e.value.cause == "MAC_FAILURE"


def test_replay(mil):
    """Same challenge twice: first one works, second one has an old SQN."""
    av = aka.generate_auth_vector(mil, SQN, SNN)
    r = aka.ue_authenticate(mil, av.rand, av.autn, SNN, 0)
    with pytest.raises(aka.AuthError) as e:
        aka.ue_authenticate(mil, av.rand, av.autn, SNN, r.sqn)
    assert e.value.cause == "SYNCH_FAILURE"


def test_amf_separation_bit_required(mil):
    """A vector with the separation bit off (old 3G style) must be refused."""
    av = aka.generate_auth_vector(mil, SQN, SNN, amf=h("0000"))
    with pytest.raises(aka.AuthError) as e:
        aka.ue_authenticate(mil, av.rand, av.autn, SNN, 0)
    assert e.value.cause == "AMF_SEPARATION"


def test_keys_bound_to_serving_network(mil):
    """Phone answers for network 999-99, but the vector was made for 242-01.

    The phone's own checks pass (the MAC doesn't include the network name),
    but RES* comes out different, so the home network rejects it.
    """
    av = aka.generate_auth_vector(mil, SQN, SNN)
    other = aka.serving_network_name("999", "99")
    r = aka.ue_authenticate(mil, av.rand, av.autn, other, 0)
    with pytest.raises(aka.AuthError):
        aka.ausf_confirm(av, r.res_star, SNN)


# --- Full flow tests -----------------------------------------------------

def _world():
    """Small helper: one home network with one customer, and that customer's phone."""
    home = HomeNetwork("242", "01")
    home.add_subscriber(Subscriber("0123456789", K, OPC))
    ue = UE("242", "01", "0123456789", K, OPC, home.key.public_bytes)
    return home, ServingNetwork("242", "01", home), ue


def test_registration_end_to_end():
    """Two logins in a row should both work, with SQN going 1 then 2."""
    _, seaf, ue = _world()
    assert seaf.register(ue) == ue.kseaf
    assert seaf.register(ue) == ue.kseaf
    assert ue.highest_sqn == 2


def test_unknown_subscriber():
    """A valid SUCI for someone who isn't a customer gets rejected."""
    home, seaf, _ = _world()
    stranger = UE("242", "01", "9999999999", K, OPC, home.key.public_bytes)
    with pytest.raises(aka.AuthError) as e:
        seaf.register(stranger)
    assert e.value.cause == "UNKNOWN_SUBSCRIBER"


def test_suci_for_other_home_network():
    """Phone encrypts with a different network's public key.

    Our home network can't decrypt it, so the tag check fails.
    """
    _, seaf, _ = _world()
    other_home = HomeNetwork("242", "01")
    ue = UE("242", "01", "0123456789", K, OPC, other_home.key.public_bytes)
    with pytest.raises(aka.AuthError) as e:
        seaf.register(ue)
    assert e.value.cause == "SUCI_INVALID"
