"""PQC exploration for report section 10. Run: uv run python scripts/pqc_lab.py"""

import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519

MSG = b"ping lab message"


def _ms(fn, runs: int) -> float:
    start = time.perf_counter()
    for _ in range(runs):
        fn()
    return (time.perf_counter() - start) / runs * 1000


def implicit_rejection_demo() -> tuple[bytes, bytes]:
    """(real secret, secret from a ciphertext with one flipped byte). decapsulate does not raise."""
    sk = mlkem.MLKEM768PrivateKey.generate()
    secret, ct = sk.public_key().encapsulate()
    bad = bytearray(ct)
    bad[0] ^= 1
    return secret, sk.decapsulate(bytes(bad))


def randomized_signing_demo() -> tuple[bytes, bytes]:
    sk = mldsa.MLDSA65PrivateKey.generate()
    return sk.sign(MSG), sk.sign(MSG)


def context_separation_demo() -> tuple[bool, bool]:
    """(verifies under the signing context, verifies under a different context)."""
    sk = mldsa.MLDSA65PrivateKey.generate()
    sig = sk.sign(MSG, b"ping/v1/envelope")
    results = []
    for ctx in (b"ping/v1/envelope", b"ping/v1/kem-bind"):
        try:
            sk.public_key().verify(sig, MSG, ctx)
            results.append(True)
        except InvalidSignature:
            results.append(False)
    return results[0], results[1]


def sizes() -> dict:
    dsa, kem = mldsa.MLDSA65PrivateKey.generate(), mlkem.MLKEM768PrivateKey.generate()
    return {
        "ML-DSA-65": {"pk": len(dsa.public_key().public_bytes_raw()), "sig": len(dsa.sign(MSG))},
        "ML-KEM-768": {
            "pk": len(kem.public_key().public_bytes_raw()),
            "ct": len(kem.public_key().encapsulate()[1]),
        },
    }


def _bench_signature(name, generate, runs):
    key = generate()
    pub = key.public_key()
    sig = key.sign(MSG)
    keygen = _ms(generate, runs)
    sign = _ms(lambda: key.sign(MSG), runs)
    verify = _ms(lambda: pub.verify(sig, MSG), runs)
    return name, keygen, sign, verify, len(pub.public_bytes_raw()), len(sig)


def _bench_kem(name, generate, runs):
    key = generate()
    pub = key.public_key()
    _, ct = pub.encapsulate()
    return (name, _ms(generate, runs), _ms(pub.encapsulate, runs),
            _ms(lambda: key.decapsulate(ct), runs), len(pub.public_bytes_raw()), len(ct))


def _bench_x25519(runs):
    key, peer = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate().public_key()

    def encaps():
        x25519.X25519PrivateKey.generate().exchange(peer)

    return ("X25519", _ms(x25519.X25519PrivateKey.generate, runs), _ms(encaps, runs),
            _ms(lambda: key.exchange(peer), runs), 32, 32)


def _section(title):
    print(f"\n== {title} ==")


def main(runs: int = 200) -> None:
    _section("1. Size and speed (ms, mean of %d runs)" % runs)
    rows = [
        _bench_signature("Ed25519", ed25519.Ed25519PrivateKey.generate, runs),
        _bench_signature("ML-DSA-65", mldsa.MLDSA65PrivateKey.generate, runs),
        _bench_x25519(runs),
        _bench_kem("ML-KEM-768", mlkem.MLKEM768PrivateKey.generate, runs),
    ]
    print(f"{'':12}{'keygen':>9}{'sign/enc':>10}{'verify/dec':>12}{'pub key B':>11}{'sig/ct B':>10}")
    for name, kg, op, back, pk, out in rows:
        print(f"{name:12}{kg:9.3f}{op:10.3f}{back:12.3f}{pk:11d}{out:10d}")

    _section("2. Implicit rejection (ML-KEM-768)")
    secret, tampered = implicit_rejection_demo()
    print(f"flipped one ciphertext byte: decapsulate returned a secret, no exception; "
          f"equal to the real one: {secret == tampered}")
    sk = mlkem.MLKEM768PrivateKey.generate()
    try:
        sk.decapsulate(sk.public_key().encapsulate()[1][:-1])
    except ValueError as e:
        print(f"wrong-length ciphertext raises ValueError: {e}")

    _section("3. Randomized signing (ML-DSA-65)")
    a, b = randomized_signing_demo()
    print(f"two signatures of the same message are identical: {a == b}")

    _section("4. Context separation (ML-DSA-65)")
    same, other = context_separation_demo()
    print(f"verifies under signing context: {same}; under a different context: {other}")

    _section("5. Parameter sets")
    print(f"{'':14}{'pub key B':>11}{'sig/ct B':>10}")
    for name, cls in (("ML-DSA-44", mldsa.MLDSA44PrivateKey), ("ML-DSA-65", mldsa.MLDSA65PrivateKey),
                      ("ML-DSA-87", mldsa.MLDSA87PrivateKey)):
        k = cls.generate()
        print(f"{name:14}{len(k.public_key().public_bytes_raw()):11d}{len(k.sign(MSG)):10d}")
    for name, cls in (("ML-KEM-768", mlkem.MLKEM768PrivateKey), ("ML-KEM-1024", mlkem.MLKEM1024PrivateKey)):
        k = cls.generate()
        print(f"{name:14}{len(k.public_key().public_bytes_raw()):11d}{len(k.public_key().encapsulate()[1]):10d}")


if __name__ == "__main__":
    main()
