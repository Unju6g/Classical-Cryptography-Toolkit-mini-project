"""Average encrypt/decrypt time of each cipher (16-character message, 2000 runs)."""
import time
from test_toolkit import tests, P

print("\nCOMPARE ALGORITHMS")
print(f"{'Cipher':<24}{'Encrypt (us)':>16}{'Decrypt (us)':>16}")
N = 2000
for name, enc, dec in tests:
    c = enc(P)
    t0 = time.perf_counter()
    for _ in range(N): enc(P)
    te = (time.perf_counter() - t0) / N
    t0 = time.perf_counter()
    for _ in range(N): dec(c)
    td = (time.perf_counter() - t0) / N
    print(f"{name:<24}{te*1e6:>16.2f}{td*1e6:>16.2f}")
