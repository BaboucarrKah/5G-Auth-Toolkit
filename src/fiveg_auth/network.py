"""A small in-memory model of the three 5G parties.

The other files are the crypto building blocks. This file puts them
together into the actual flow, so you can run a full registration from
start to finish, see what each party does, and try to attack it.

There's no real networking here. The "messages" are just function calls
between objects, which keeps it easy to follow and test.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from . import aka, suci
from .events import EventLog
from .milenage import Milenage

PROFILE_B = 2   # the number the spec uses to say "this SUCI uses Profile B"

# Every party takes an optional log function so the CLI can print what's
# happening. It gets (who, message), e.g. ("UE", "sending SUCI").
LogFn = Callable[[str, str], None]


def _no_log(actor: str, msg: str) -> None:
    """Default logger that does nothing. Keeps the tests quiet."""


@dataclass
class Subscriber:
    """One customer in the home network's database (the UDM)."""
    msin: str        # the subscriber number, the private part of the IMSI
    k: bytes         # secret key, same as on the SIM card
    opc: bytes       # operator constant for this card
    sqn: int = 0     # sequence number, goes up by one every login


@dataclass
class Suci:
    """A SUCI as the phone sends it.

    Country and operator code are in clear text, because the network
    needs them to know which home network to send it to. Only the
    subscriber number is encrypted (in `output`).
    """
    mcc: str
    mnc: str
    scheme: int      # which protection scheme (2 = Profile B)
    key_id: int      # which home network key was used, so keys can be rotated
    output: bytes    # the encrypted part from suci.conceal()

    def __str__(self) -> str:
        # Readable form, close to the format in TS 23.003
        return (f"suci-0-{self.mcc}-{self.mnc}-0000-{self.scheme}-"
                f"{self.key_id}-{self.output.hex()}")


class UE:
    """The phone with its SIM card.

    The SIM holds K, OPc and the home network's public key. It also
    remembers the highest SQN it has seen, which is how it spots replays.
    """

    def __init__(self, mcc: str, mnc: str, msin: str, k: bytes, opc: bytes,
                 hn_public_key: bytes, key_id: int = 1, log: LogFn = _no_log):
        self.mcc, self.mnc, self.msin = mcc, mnc, msin
        self._mil = Milenage(k, opc)
        self._hn_pub = hn_public_key
        self._key_id = key_id
        self.highest_sqn = 0                 # nothing accepted yet
        self.kseaf: bytes | None = None      # filled in after a successful login
        self._log = log

    @property
    def supi(self) -> str:
        """The permanent ID. Only used for printing, it's never sent anywhere."""
        return f"imsi-{self.mcc}{self.mnc}{self.msin}"

    def make_suci(self) -> Suci:
        """Step 1: hide the ID and send it to the network."""
        # Pack the number as BCD, then encrypt it with the home network key
        out = suci.conceal(self._hn_pub, suci.msin_to_bcd(self.msin))
        s = Suci(self.mcc, self.mnc, PROFILE_B, self._key_id, out)
        self._log("UE", f"sending {s}")
        return s

    def on_auth_request(self, rand: bytes, autn: bytes, snn: bytes) -> bytes:
        """Step 3: the network sent a challenge. Check it and answer.

        If AUTN is fake or old, aka.ue_authenticate raises an error and
        the phone never answers.
        """
        self._log("UE", "verifying AUTN")
        result = aka.ue_authenticate(self._mil, rand, autn, snn, self.highest_sqn)

        # Remember this SQN, so the same challenge can't be used again
        self.highest_sqn = result.sqn
        self.kseaf = result.kseaf
        self._log("UE", f"network OK, SQN={result.sqn}, sending RES*")
        return result.res_star


@dataclass
class HomeNetwork:
    """The home operator. In real life these are separate functions
    (UDM, SIDF and AUSF), but here they're one object to keep it simple.
    """
    mcc: str
    mnc: str
    key: suci.HomeNetworkKey = field(default_factory=suci.HomeNetworkKey.generate)
    key_id: int = 1
    subscribers: dict[str, Subscriber] = field(default_factory=dict)
    log: LogFn = _no_log

    # Where security events go (for the SIEM). None means "don't log",
    # so the tests and the normal simulator work exactly as before.
    events: EventLog | None = None

    # Logins that have started but not finished yet. The key is RAND, so
    # when the answer comes back we can find the right vector again.
    # We also remember who it was and which cell they were in, so a
    # failure later on can be logged with that information.
    _pending: dict[bytes, tuple[aka.HomeAuthVector, bytes, Subscriber, str]] = field(default_factory=dict)

    def add_subscriber(self, sub: Subscriber) -> None:
        self.subscribers[sub.msin] = sub

    def _event(self, event_type: str, sub: Subscriber | None, snn: bytes,
                cell: str, **fields) -> None:
        """Send one security event, if logging is turned on."""
        if self.events is None:
            return
        supi = f"imsi-{self.mcc}{self.mnc}{sub.msin}" if sub else None
        self.events.emit(event_type, supi=supi, cell=cell,
                            serving_network=snn.decode(), **fields)

    def resolve_suci(self, s: Suci) -> Subscriber:
        """SIDF: decrypt the SUCI and find the customer."""
        # Only accept the scheme and key we actually support
        if s.scheme != PROFILE_B or s.key_id != self.key_id:
            raise aka.AuthError("UNSUPPORTED", "unknown scheme or key id")

        # Decrypt. If the SUCI was changed on the way, the tag check fails
        # and we turn that into an AuthError so the caller only has to
        # deal with one kind of error.
        try:
            msin = suci.bcd_to_msin(self.key.deconceal(s.output))
        except suci.SuciError as e:
            raise aka.AuthError("SUCI_INVALID", str(e)) from e

        if msin not in self.subscribers:
            raise aka.AuthError("UNKNOWN_SUBSCRIBER", "no such subscriber")
        self.log("SIDF", f"SUCI resolved to imsi-{self.mcc}{self.mnc}{msin}")
        return self.subscribers[msin]

    def authenticate(self, s: Suci, snn: bytes,
                     cell: str = "unknown") -> aka.ServingAuthVector:
        """Step 2: find the customer and make a challenge for them."""
        try:
            sub = self.resolve_suci(s)
        except aka.AuthError as e:
            # We don't know who it is yet, so no subscriber in this event
            self._event("auth_failure", None, snn, cell, cause=e.cause)
            raise

        # New SQN for every login, so the phone can tell new from old
        sub.sqn += 1
        av = aka.generate_auth_vector(Milenage(sub.k, sub.opc),
                                      sub.sqn.to_bytes(6, "big"), snn)

        # Save the full vector (with XRES* and KAUSF) for later, and also
        # which network asked, so we can check the answer is for the same one
        self._pending[av.rand] = (av, snn, sub, cell)
        self.log("AUSF", f"auth vector generated (SQN={sub.sqn})")

        # The serving network only gets the stripped-down version
        return aka.to_serving_vector(av)

    def confirm(self, rand: bytes, res_star: bytes) -> bytes:
        """Step 5: the final check. Give out KSEAF only if RES* is right."""
        if rand not in self._pending:
            raise aka.AuthError("NO_CONTEXT", "no pending authentication")
        
        # pop removes it, so the same login can't be confirmed twice
        av, snn, sub, cell = self._pending.pop(rand)
        try:
            kseaf = aka.ausf_confirm(av, res_star, snn)
        except aka.AuthError as e:
            self._event("auth_failure", sub, snn, cell, cause=e.cause)
            raise
        self._event("auth_success", sub, snn, cell)
        self.log("AUSF", "RES* matches XRES*, KSEAF released")
        return kseaf

    def report_failure(self, rand: bytes, cause: str) -> None:
        """The serving network tells us the login failed on its side.

        For example the phone refused our challenge (MAC or SQN check).
        We look up who it was from RAND and log it.
        """
        if rand not in self._pending:
            return
        _, snn, sub, cell = self._pending.pop(rand)
        self._event("auth_failure", sub, snn, cell, cause=cause)


class ServingNetwork:
    """The network the phone is connected to right now (the SEAF).

    It sits in the middle: it passes messages between the phone and the
    home network, but it doesn't know K and never sees XRES*.
    """

    def __init__(self, mcc: str, mnc: str, home: HomeNetwork, log: LogFn = _no_log):
        self.snn = aka.serving_network_name(mcc, mnc)
        self.home = home
        self._log = log

    def register(self, ue: UE) -> bytes:
        """Run one full login. Returns KSEAF if everything checks out."""
        # 1. Phone sends its SUCI
        s = ue.make_suci()

        # 2. Ask the home network for a challenge
        sv = self.home.authenticate(s, self.snn)
        self._log("SEAF", f"auth request to UE, SNN={self.snn.decode()}")

        # 3. Pass the challenge to the phone and get RES* back
        res_star = ue.on_auth_request(sv.rand, sv.autn, self.snn)

        # 4. Quick check on our side with the hash we got
        if not aka.seaf_check(sv, res_star):
            raise aka.AuthError("RES_MISMATCH", "HRES* does not match HXRES*")
        self._log("SEAF", "HRES* OK, asking AUSF to confirm")

        # 5. The home network makes the real decision and gives us KSEAF
        kseaf = self.home.confirm(sv.rand, res_star)

        # Sanity check: the phone and the network should now have the
        # exact same key without ever having sent it to each other
        if kseaf != ue.kseaf:
            raise aka.AuthError("KEY_MISMATCH", "UE and network keys differ")
        self._log("SEAF", f"registration complete, KSEAF={kseaf.hex()[:16]}...")
        return kseaf
