"""MILENAGE authentication functions (3GPP TS 35.206).

MILENAGE is the set of functions that runs on the SIM card and in the home
network. Both sides share a secret 128-bit key K and an operator constant
OPc. When the network sends a random challenge RAND, both sides can compute
the same values from it:

    f1  / f1*  network authentication code (MAC-A / MAC-S)
    f2         response RES (and XRES on the network side)
    f3         cipher key CK
    f4         integrity key IK
    f5  / f5*  anonymity key AK, used to hide the sequence number

Everything is built from plain AES-128. The trick is that each function
rotates and XORs the data a bit differently before the last AES call, so
the outputs end up independent of each other even though they all start
from the same RAND.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16  # AES block size in bytes, and also the size of K, OPc and RAND

# How far each function rotates its input. The spec gives these in bits
# (64, 0, 32, 64, 96), but since they are all multiples of 8 I can rotate
# whole bytes instead, which is a lot simpler.
_R1, _R2, _R3, _R4, _R5 = 8, 0, 4, 8, 12

# The constants c1 to c5. They are 16 bytes each, all zeros except the last
# byte (0, 1, 2, 4, 8). This is what makes f2, f3, f4 and f5* give different
# results even though they go through the same steps.
_C1, _C2, _C3, _C4, _C5 = (bytes(15) + bytes([v]) for v in (0, 1, 2, 4, 8))


def xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of the same length."""
    # zip would silently cut off the longer one, so I check the length
    # first. A length bug here would be really hard to find later.
    if len(a) != len(b):
        raise ValueError("xor operands must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def _rot(x: bytes, n: int) -> bytes:
    """Rotate left by n bytes. The bytes that fall off the front go to the back."""
    return x[n:] + x[:n]


def _aes(key: bytes, block: bytes) -> bytes:
    """Encrypt exactly one 16-byte block with AES-128."""
    # ECB is normally a bad idea, but here we only ever encrypt one block
    # and use AES as a building block, not to encrypt a message. With a
    # single block ECB is just "raw AES", which is what the spec wants.
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def compute_opc(k: bytes, op: bytes) -> bytes:
    """Make OPc from the operator's OP and the subscriber's K.

    OPc = AES_K(OP) xor OP

    OP is the same for every customer of an operator. If it was stored on
    every SIM card, one hacked card would leak it for everyone. OPc is
    mixed with K, so it's different per card and doesn't reveal OP.
    """
    return xor(_aes(k, op), op)


@dataclass(frozen=True)
class MilenageOutput:
    """All seven outputs from one run, so callers don't have to call each function."""
    mac_a: bytes   # f1,  8 bytes  - proves the network knows K
    mac_s: bytes   # f1*, 8 bytes  - same idea, used for resynchronisation
    res: bytes     # f2,  8 bytes  - proves the SIM knows K
    ck: bytes      # f3, 16 bytes  - key for encrypting traffic
    ik: bytes      # f4, 16 bytes  - key for integrity protection
    ak: bytes      # f5,  6 bytes  - hides SQN in AUTN
    ak_s: bytes    # f5*, 6 bytes  - hides SQN during resynchronisation


class Milenage:
    """MILENAGE for one subscriber.

    I made this a class so K and OPc are set once, instead of passing them
    into every single function call like I did in the first version.
    """

    def __init__(self, k: bytes, opc: bytes) -> None:
        # Fail early if the keys are the wrong size, instead of getting a
        # confusing error from deep inside AES later
        if len(k) != BLOCK or len(opc) != BLOCK:
            raise ValueError("K and OPc must be 16 bytes")
        self._k = k
        self._opc = opc

    @classmethod
    def from_op(cls, k: bytes, op: bytes) -> Milenage:
        """Alternative constructor if you have OP instead of OPc."""
        return cls(k, compute_opc(k, op))

    def _temp(self, rand: bytes) -> bytes:
        """Step 1 for every function: TEMP = AES_K(RAND xor OPc).

        Every f-function starts from this value, so compute_all only
        calculates it once.
        """
        if len(rand) != BLOCK:
            raise ValueError("RAND must be 16 bytes")
        return _aes(self._k, xor(rand, self._opc))

    def _out(self, temp: bytes, r: int, c: bytes) -> bytes:
        """Shared recipe for f2 to f5*.

        OUT = AES_K( rotate(TEMP xor OPc, r) xor c ) xor OPc

        Only r and c change between the functions.
        """
        x = xor(temp, self._opc)   # mix TEMP with OPc
        x = _rot(x, r)             # rotate by this function's amount
        x = xor(x, c)              # XOR in this function's constant
        return xor(_aes(self._k, x), self._opc)

    def _out1(self, temp: bytes, sqn: bytes, amf: bytes) -> bytes:
        """Recipe for f1 and f1*. Same idea, but SQN and AMF are mixed in too.

        This is why the MAC also protects the sequence number: change
        SQN and you get a completely different MAC.
        """
        if len(sqn) != 6 or len(amf) != 2:
            raise ValueError("SQN must be 6 bytes and AMF 2 bytes")

        # SQN (6) + AMF (2) is only 8 bytes, so the spec repeats it to fill 16
        in1 = sqn + amf + sqn + amf

        x = xor(in1, self._opc)
        x = _rot(x, _R1)
        x = xor(x, _C1)
        x = xor(x, temp)   # here TEMP is added at the end instead of the start
        return xor(_aes(self._k, x), self._opc)

    # --- The actual functions --------------------------------------------
    # Each one just picks the part of an OUT block it needs.

    def f1(self, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
        return self._out1(self._temp(rand), sqn, amf)[:8]    # first half of OUT1

    def f1_star(self, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
        return self._out1(self._temp(rand), sqn, amf)[8:]    # second half of OUT1

    def f2_f5(self, rand: bytes) -> tuple[bytes, bytes]:
        """Returns (RES, AK).

        f2 and f5 come from the same OUT2 block (RES from the end, AK from
        the start), so I return both from one call instead of doing the
        same AES twice.
        """
        out2 = self._out(self._temp(rand), _R2, _C2)
        return out2[8:], out2[:6]

    def f3(self, rand: bytes) -> bytes:
        return self._out(self._temp(rand), _R3, _C3)          # all of OUT3

    def f4(self, rand: bytes) -> bytes:
        return self._out(self._temp(rand), _R4, _C4)          # all of OUT4

    def f5_star(self, rand: bytes) -> bytes:
        return self._out(self._temp(rand), _R5, _C5)[:6]      # first 6 bytes of OUT5

    def compute_all(self, rand: bytes, sqn: bytes, amf: bytes) -> MilenageOutput:
        """Run everything at once. TEMP is only calculated one time.

        The home network needs almost all the values when it builds an
        auth vector, so this saves a bunch of AES calls.
        """
        temp = self._temp(rand)
        out1 = self._out1(temp, sqn, amf)
        out2 = self._out(temp, _R2, _C2)
        return MilenageOutput(
            mac_a=out1[:8],
            mac_s=out1[8:],
            res=out2[8:],
            ck=self._out(temp, _R3, _C3),
            ik=self._out(temp, _R4, _C4),
            ak=out2[:6],
            ak_s=self._out(temp, _R5, _C5)[:6],
        )
