# Security tests

Green tests only show that the code works when everything goes right. This page shows what happens when things go wrong: first when someone attacks the protocol, and then when I break the code on purpose to see if the tests notice.

## Attack scenarios

The simulator has four built-in attacks. Each one first runs a normal registration, then tries the attack.

```bash
5g-auth simulate --attack replay
5g-auth simulate --attack fake-network
5g-auth simulate --attack tamper-suci
5g-auth simulate --attack wrong-network
```

All four are blocked, and each one by a different part of the protocol.

| Attack | What the attacker does | What stops it | Error |
|---|---|---|---|
| `replay` | Records a real challenge (RAND/AUTN) and sends it to the phone again later | The phone only accepts a sequence number (SQN) higher than any it has seen before | `SYNCH_FAILURE` |
| `fake-network` | A fake base station without the subscriber key sends its own challenge | The MAC in AUTN can't be produced without the key K | `MAC_FAILURE` |
| `tamper-suci` | Flips one bit in the encrypted identity on its way to the home network | The HMAC tag on the SUCI no longer matches | `SUCI_INVALID` |
| `wrong-network` | A rogue network reuses a challenge that was made for another network | RES* is calculated with the network name inside it, so the home network rejects the answer | `RES_MISMATCH` |

### Replay

```
ATTACK | capturing a challenge and replaying it to the UE
    UE | verifying AUTN
    UE | network OK, SQN=2, sending RES*
    UE | verifying AUTN
ATTACK | blocked: SYNCH_FAILURE (SQN not fresh, possible replay)
```

The first copy of the challenge is genuine, so the phone accepts it. The second copy is identical and still has a valid MAC, but SQN=2 has already been used, so the phone refuses it.

### Fake base station

```
ATTACK | fake base station without K sends a forged AUTN
    UE | verifying AUTN
ATTACK | blocked: MAC_FAILURE (network authentication failed)
```

This is what an IMSI catcher would try. It can pretend to be a network, but without the key in the SIM it can only send random data. The phone recalculates the MAC, sees it doesn't match and never answers. 2G had no check like this, which is why fake base stations used to work so well.

### Tampered SUCI

```
ATTACK | flipping one bit in the SUCI ciphertext
ATTACK | blocked: SUCI_INVALID (MAC verification failed)
```

The attacker can't read the encrypted identity, but could try to corrupt it. The home network checks the tag before decrypting anything (encrypt-then-MAC), so a single flipped bit is enough to reject it.

### Wrong serving network

```
ATTACK | rogue network reuses a vector made for another SNN
    UE | verifying AUTN
    UE | network OK, SQN=2, sending RES*
ATTACK | blocked: RES_MISMATCH (RES* does not match XRES*)
```

This one is the most interesting. The phone is actually fooled: the challenge really did come from the home network, so it says "network OK" and answers. But RES* is bound to the serving network's name, so when the answer reaches the home network it doesn't match. This is why 5G gives the final decision to the home network and only gives the serving network a hash of the expected answer.

## Break-it tests

To check that each security mechanism actually matters, and that the test suite would notice if it broke, I changed the code on purpose and ran `pytest` again. Each change was reverted afterwards.

| Change | File | Tests failed | Caught by |
|---|---|---|---|
| Removed the SQN freshness check | `aka.py` | 1 of 30 | `test_replay` |
| Changed rotation `_R3` from 4 to 5 | `milenage.py` | 1 of 30 | `test_test_set_1` (3GPP test vector) |
| Changed SUCI tag length from 8 to 16 bytes | `suci.py` | 2 of 30 | Both 3GPP SUCI test vectors |

### 1. Removing the replay check

```python
sqn_int = int.from_bytes(sqn, "big")
# if sqn_int <= highest_sqn:
#     raise AuthError("SYNCH_FAILURE", "SQN not fresh, possible replay")
```

Only `test_replay` failed, with `DID NOT RAISE AuthError`. The simulator showed the phone accepting the same challenge twice and ended with `ATTACK | NOT blocked`. So those two lines are the only thing in the project that stops a replay, and there is a test that guards them.

### 2. One wrong number in MILENAGE

```python
_R1, _R2, _R3, _R4, _R5 = 8, 0, 5, 8, 12   # _R3 should be 4
```

This changes f3, the function that produces the cipher key CK. I expected a lot of tests to fail, but only one did:

```
assert out.ck.hex() == "b40ba9a3c58b2a05bbf0d987b21bf8cb"   # f3
- b40ba9a3c58b2a05bbf0d987b21bf8cb
+ 127beba50d2e724d1b82006d880f0fb7
```

The phone and the network both use the same MILENAGE code. When f3 is wrong, it's wrong on both sides in exactly the same way, so they still agree, the login works and every round-trip test passes. Only the official 3GPP test vector notices.

### 3. Wrong SUCI tag length

```python
MAC_LEN = 16   # should be 8
```

Both tests against the official 3GPP SUCI example failed. Encrypting produced a SUCI that was 8 bytes too long (everything matched the spec up to the tag, then kept going). Decrypting the official 46-byte SUCI failed with `scheme output too short`, because the code now expected at least 50 bytes.

Every other SUCI test still passed: round trip, unlinkability, tampering and wrong key. My phone and my home network both used 16 bytes, so they understood each other. A real phone sends 8, and every one of them would have been rejected.

## What this shows

- **Each attack is stopped by exactly one mechanism.** Remove any of them and an attack gets through.
- **Working together is not the same as being correct.** In two of the three break-it tests, both sides made the same mistake and still logged in fine. Without the official 3GPP test vectors, those bugs would have gone unnoticed. In a real network, the result would be a system that passes all its own tests but can't talk to a single real SIM card.

## Run it yourself

```bash
pip install -e ".[dev]"
pytest -v
5g-auth simulate --attack replay
```

To repeat a break-it test, make one of the changes above, run `pytest -v`, and then revert it.
