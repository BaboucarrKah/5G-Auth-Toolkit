"""SUCI concealment with ECIES Profile B (3GPP TS 33.501, Annex C).

The problem: in 2G/3G/4G the phone often sent its permanent ID (the IMSI)
in clear text. Fake base stations called IMSI catchers used that to track
people.

The 5G fix: the phone never sends its permanent ID (SUPI) in clear text.
It encrypts it with the home network's public key, and that encrypted
version is the SUCI. Only the home network (the part called SIDF) has the
private key and can decrypt it.

How Profile B works, step by step:
    1. The phone makes a brand new P-256 key pair for every single SUCI
    2. ECDH between that new key and the home network public key gives a
       shared secret Z that only the phone and the home network can know
    3. A KDF (ANSI X9.63 with SHA-256) stretches Z into three keys:
         enc_key (16 bytes) || icb (16 bytes) || mac_key (32 bytes)
    4. The ID is encrypted with AES-128-CTR, and the ciphertext gets an
       HMAC-SHA-256 tag (cut down to 8 bytes)
    5. The phone sends:  its new public key || ciphertext || tag

Because step 1 uses a new key every time, two SUCIs from the same person
look completely unrelated. So someone listening can't even tell that it's
the same phone twice.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CURVE = ec.SECP256R1()   # the P-256 curve that Profile B uses
PUBKEY_LEN = 33          # compressed point: 1 prefix byte + 32 byte x-coordinate
MAC_LEN = 8              # the spec only keeps the first 8 bytes of the HMAC


class SuciError(Exception):
    """Something was wrong with a SUCI: bad format, bad key or bad tag."""


@dataclass(frozen=True)
class SuciCiphertext:
    """The three parts of the scheme output, kept apart so they're easy to work with."""
    ephemeral_public_key: bytes
    ciphertext: bytes
    mac_tag: bytes

    def to_bytes(self) -> bytes:
        """Glue the parts together in the order the spec says."""
        return self.ephemeral_public_key + self.ciphertext + self.mac_tag

    @classmethod
    def from_bytes(cls, data: bytes) -> SuciCiphertext:
        """Split raw bytes back into the three parts.

        The public key and tag have fixed lengths, so everything in
        between must be the ciphertext.
        """
        # If it's not even long enough for key + tag + 1 byte of data,
        # there's no point continuing
        if len(data) <= PUBKEY_LEN + MAC_LEN:
            raise SuciError("scheme output too short")
        return cls(data[:PUBKEY_LEN], data[PUBKEY_LEN:-MAC_LEN], data[-MAC_LEN:])


def _compressed(pub: ec.EllipticCurvePublicKey) -> bytes:
    """Public key as 33 bytes instead of 65. That's what the spec sends."""
    return pub.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def _derive_keys(shared_secret: bytes, eph_pub: bytes) -> tuple[bytes, bytes, bytes]:
    """Turn the ECDH secret Z into (enc_key, icb, mac_key).

    The ephemeral public key is fed in as "sharedinfo", so the keys are
    tied to this exact SUCI and can't be reused with another one.
    """
    okm = X963KDF(algorithm=hashes.SHA256(), length=64, sharedinfo=eph_pub).derive(shared_secret)
    # 64 bytes out, split into the three pieces we need
    return okm[:16], okm[16:32], okm[32:]


def _aes_ctr(key: bytes, icb: bytes, data: bytes) -> bytes:
    """AES-128 in counter mode. icb is the starting counter value."""
    # CTR just XORs a keystream onto the data, so encrypting and
    # decrypting are the exact same operation. I use this one function
    # for both.
    c = Cipher(algorithms.AES(key), modes.CTR(icb)).encryptor()
    return c.update(data) + c.finalize()


def _mac(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA-256 cut down to 8 bytes."""
    return hmac.new(key, data, sha256).digest()[:MAC_LEN]


class HomeNetworkKey:
    """The home network's key pair.

    The public key is put on every SIM card. The private key should only
    ever exist inside the SIDF (in real networks, inside an HSM).
    """

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self._priv = private_key

    @classmethod
    def generate(cls) -> HomeNetworkKey:
        """Make a fresh random key pair."""
        return cls(ec.generate_private_key(CURVE))

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> HomeNetworkKey:
        """Load a known private key. Used in the tests with the spec's key."""
        return cls(ec.derive_private_key(int.from_bytes(raw, "big"), CURVE))

    @property
    def public_bytes(self) -> bytes:
        """The public key the phone needs, in compressed form."""
        return _compressed(self._priv.public_key())

    def deconceal(self, scheme_output: bytes) -> bytes:
        """Home network side: take a SUCI and get the real ID back."""
        s = SuciCiphertext.from_bytes(scheme_output)

        # Load the phone's one-time public key. If someone sends garbage
        # that isn't a valid point on the curve, stop here.
        try:
            eph = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, s.ephemeral_public_key)
        except ValueError as e:
            raise SuciError("invalid ephemeral public key") from e

        # Same ECDH as the phone did, just from the other side.
        # (our private key + their public key) gives the same Z as
        # (their private key + our public key).
        z = self._priv.exchange(ec.ECDH(), eph)
        enc_key, icb, mac_key = _derive_keys(z, s.ephemeral_public_key)

        # Check the tag BEFORE decrypting. If the tag is wrong the data
        # has been changed (or was made with another key), and we don't
        # want to touch it at all.
        if not hmac.compare_digest(_mac(mac_key, s.ciphertext), s.mac_tag):
            raise SuciError("MAC verification failed")

        return _aes_ctr(enc_key, icb, s.ciphertext)


def conceal(home_public_key: bytes, plaintext: bytes,
            ephemeral_key: ec.EllipticCurvePrivateKey | None = None) -> bytes:
    """Phone side: encrypt the ID into a SUCI.

    ephemeral_key is only passed in by the tests, so I can check against
    the exact numbers in the spec. In normal use it's left empty and a new
    key is made every time.
    """
    hn_pub = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, home_public_key)

    # New one-time key pair for this SUCI only
    eph = ephemeral_key or ec.generate_private_key(CURVE)
    eph_pub = _compressed(eph.public_key())

    # Shared secret with the home network, then the three keys
    z = eph.exchange(ec.ECDH(), hn_pub)
    enc_key, icb, mac_key = _derive_keys(z, eph_pub)

    # Encrypt first, then MAC the ciphertext (encrypt-then-MAC)
    ct = _aes_ctr(enc_key, icb, plaintext)
    return SuciCiphertext(eph_pub, ct, _mac(mac_key, ct)).to_bytes()


# --- Helpers for the ID format ----------------------------------------------
#
# The part of the IMSI that gets encrypted is the MSIN (the subscriber
# number). The spec packs it as BCD: two digits per byte, with the digits
# swapped inside each byte. If there's an odd number of digits the last
# spot is filled with F. So "001002086" becomes 00 01 20 80 F6.

def msin_to_bcd(msin: str) -> bytes:
    """'001002086' -> b'\\x00\\x01\\x20\\x80\\xf6'"""
    if not msin.isdigit():
        raise ValueError("MSIN must be digits")
    if len(msin) % 2:
        msin += "F"   # pad odd length
    # Take two digits at a time and swap them: "12" -> "21"
    return bytes.fromhex("".join(msin[i + 1] + msin[i] for i in range(0, len(msin), 2)))


def bcd_to_msin(data: bytes) -> str:
    """The reverse: swap back each byte's digits and drop the F padding."""
    digits = "".join(f"{b:02X}"[::-1] for b in data)
    return digits.rstrip("F")
