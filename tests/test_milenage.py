"""Tests for MILENAGE against the official 3GPP numbers (TS 35.208, test set 1).

If these pass, my implementation gives exactly the same output as the
spec. Everything else in the project builds on this, so it's the most
important test file.
"""

import pytest

from fiveg_auth.milenage import Milenage, compute_opc

h = bytes.fromhex

# Inputs from TS 35.208 test set 1
K = h("465b5ce8b199b49faa5f0a2ee238a6bc")
RAND = h("23553cbe9637a89d218ae64dae47bf35")
SQN = h("ff9bb4d0b607")
AMF = h("b9b9")
OP = h("cdc202d5123e20f62b6d676ac72cb318")
OPC = h("cd63cb71954a9f4e48a5994e37a02baf")


@pytest.fixture
def mil():
    return Milenage(K, OPC)


def test_opc():
    """OPc made from OP and K should match the spec."""
    assert compute_opc(K, OP) == OPC


def test_from_op_matches_opc():
    """Making the object from OP or from OPc should give the same results."""
    assert Milenage.from_op(K, OP).f3(RAND) == Milenage(K, OPC).f3(RAND)


def test_test_set_1(mil):
    """All seven outputs compared with the expected values from the spec."""
    out = mil.compute_all(RAND, SQN, AMF)
    assert out.mac_a.hex() == "4a9ffac354dfafb3"                    # f1
    assert out.mac_s.hex() == "01cfaf9ec4e871e9"                    # f1*
    assert out.res.hex() == "a54211d5e3ba50bf"                      # f2
    assert out.ck.hex() == "b40ba9a3c58b2a05bbf0d987b21bf8cb"       # f3
    assert out.ik.hex() == "f769bcd751044604127672711c6d3441"       # f4
    assert out.ak.hex() == "aa689c648370"                           # f5
    assert out.ak_s.hex() == "451e8beca43b"                         # f5*


def test_individual_functions_match_compute_all(mil):
    """compute_all is a shortcut, so it must give the same as calling each function."""
    out = mil.compute_all(RAND, SQN, AMF)
    assert mil.f1(RAND, SQN, AMF) == out.mac_a
    assert mil.f1_star(RAND, SQN, AMF) == out.mac_s
    assert mil.f2_f5(RAND) == (out.res, out.ak)
    assert mil.f3(RAND) == out.ck
    assert mil.f4(RAND) == out.ik
    assert mil.f5_star(RAND) == out.ak_s


@pytest.mark.parametrize("k,opc", [(bytes(15), OPC), (K, bytes(17))], ids=["short K", "long opc"])
def test_rejects_bad_key_lengths(k, opc):
    """K or OPc with the wrong length should be refused right away."""
    with pytest.raises(ValueError):
        Milenage(k, opc)


def test_rejects_bad_rand(mil):
    """Same for RAND."""
    with pytest.raises(ValueError):
        mil.f3(bytes(15))
