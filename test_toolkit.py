"""Round-trip test of all eight ciphers."""
from crypto_core import *

P = "NETWORK SECURITY"
MK = "QWERTYUIOPASDFGHJKLZXCVBNM"
OK = "XMCKLQPZRTBVDAWY"
tests = [
    ("Caesar (key=5)", lambda t: caesar_encrypt(t, 5), lambda t: caesar_decrypt(t, 5)),
    ("Monoalphabetic", lambda t: mono_encrypt(t, MK), lambda t: mono_decrypt(t, MK)),
    ("Playfair (MONARCHY)", lambda t: playfair_transform(t, "MONARCHY"), lambda t: playfair_transform(t, "MONARCHY", True)),
    ("Hill (2x2)", hill_encrypt, hill_decrypt),
    ("Vigenere (KEY)", lambda t: vigenere_transform(t, "KEY"), lambda t: vigenere_transform(t, "KEY", True)),
    ("One-Time Pad", lambda t: otp_transform(t, OK), lambda t: otp_transform(t, OK, True)),
    ("Rail Fence (3)", lambda t: rail_fence_encrypt(t, 3), lambda t: rail_fence_decrypt(t, 3)),
    ("Columnar (ZEBRA)", lambda t: columnar_encrypt(t, "ZEBRA"), lambda t: columnar_decrypt(t, "ZEBRA")),
]
print("=" * 74)
print(f"{'Cipher':<22}{'Ciphertext':<24}{'Decrypted':<22}Result")
print("-" * 74)
passed = 0
for name, enc, dec in tests:
    c = enc(P); r = dec(c)
    ok = r.replace(" ", "").startswith(P.replace(" ", ""))
    passed += ok
    print(f"{name:<22}{c:<24}{r:<22}{'PASS' if ok else 'FAIL'}")
print("-" * 74)
print(f"{passed}/{len(tests)} tests passed.")
