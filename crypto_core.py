import random, string
A = string.ascii_uppercase

def caesar(text, shift):
    out = []
    for ch in text:
        if ch.isalpha() and ch.isascii():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)
def caesar_encrypt(t, s): return caesar(t, s)
def caesar_decrypt(t, s): return caesar(t, -s)

def validate_mono_key(key):
    return len(key) == 26 and set(key.upper()) == set(A)
def _mono(text, src, dst):
    table = {}
    for s, d in zip(src, dst):
        table[s] = d; table[s.lower()] = d.lower()
    return "".join(table.get(c, c) for c in text)
def mono_encrypt(t, key): return _mono(t, A, key.upper())
def mono_decrypt(t, key): return _mono(t, key.upper(), A)

def _pf_square(key):
    seen = []
    for c in (key.upper() + A).replace("J", "I"):
        if c in A and c not in seen:
            seen.append(c)
    return seen
def _pf_prepare(text):
    s = [c for c in text.upper().replace("J", "I") if c in A]
    out, i = [], 0
    while i < len(s):
        a = s[i]
        b = s[i + 1] if i + 1 < len(s) else "X"
        if a == b:
            out.append((a, "X")); i += 1
        else:
            out.append((a, b)); i += 2
    return out
def playfair_transform(text, key, decrypt=False):
    sq = _pf_square(key)
    pos = {c: divmod(i, 5) for i, c in enumerate(sq)}
    step = -1 if decrypt else 1
    if decrypt:
        s = [c for c in text.upper().replace("J", "I") if c in A]
        if len(s) % 2: raise ValueError("Playfair ciphertext must have an even number of letters.")
        pairs = [(s[i], s[i + 1]) for i in range(0, len(s), 2)]
    else:
        pairs = _pf_prepare(text)
    out = []
    for a, b in pairs:
        r1, c1 = pos[a]; r2, c2 = pos[b]
        if r1 == r2:
            out += [sq[r1 * 5 + (c1 + step) % 5], sq[r2 * 5 + (c2 + step) % 5]]
        elif c1 == c2:
            out += [sq[((r1 + step) % 5) * 5 + c1], sq[((r2 + step) % 5) * 5 + c2]]
        else:
            out += [sq[r1 * 5 + c2], sq[r2 * 5 + c1]]
    return "".join(out)

HILL_KEY = [[3, 3], [2, 5]]
HILL_INV = [[15, 17], [20, 9]]
def _hill(text, m):
    s = [ord(c) - 65 for c in text.upper() if c in A]
    if len(s) % 2: s.append(ord('X') - 65)
    out = []
    for i in range(0, len(s), 2):
        x, y = s[i], s[i + 1]
        out.append(chr((m[0][0] * x + m[0][1] * y) % 26 + 65))
        out.append(chr((m[1][0] * x + m[1][1] * y) % 26 + 65))
    return "".join(out)
def hill_encrypt(t): return _hill(t, HILL_KEY)
def hill_decrypt(t): return _hill(t, HILL_INV)

def vigenere_transform(text, key, decrypt=False):
    k = [ord(c) - 65 for c in key.upper() if c in A]
    if not k: raise ValueError("The keyword must contain letters.")
    out, j = [], 0
    for ch in text:
        if ch.isalpha() and ch.isascii():
            base = ord('A') if ch.isupper() else ord('a')
            s = -k[j % len(k)] if decrypt else k[j % len(k)]
            out.append(chr((ord(ch) - base + s) % 26 + base)); j += 1
        else:
            out.append(ch)
    return "".join(out)

def otp_generate_key(text):
    n = sum(1 for c in text if c.isalpha() and c.isascii())
    return "".join(random.SystemRandom().choice(A) for _ in range(n))
def otp_transform(text, key, decrypt=False):
    k = [ord(c) - 65 for c in key.upper() if c in A]
    n = sum(1 for c in text if c.isalpha() and c.isascii())
    if len(k) < n:
        raise ValueError(f"The key needs at least {n} letters (message has {n} letters).")
    out, j = [], 0
    for ch in text:
        if ch.isalpha() and ch.isascii():
            base = ord('A') if ch.isupper() else ord('a')
            s = -k[j] if decrypt else k[j]
            out.append(chr((ord(ch) - base + s) % 26 + base)); j += 1
        else:
            out.append(ch)
    return "".join(out)

def _rail_pattern(n, rails):
    if rails == 1: return [0] * n
    p, r, d = [], 0, 1
    for _ in range(n):
        p.append(r)
        if r == 0: d = 1
        elif r == rails - 1: d = -1
        r += d
    return p
def rail_fence_encrypt(text, rails):
    p = _rail_pattern(len(text), rails)
    return "".join(text[i] for r in range(rails) for i in range(len(text)) if p[i] == r)
def rail_fence_decrypt(text, rails):
    p = _rail_pattern(len(text), rails)
    order = [i for r in range(rails) for i in range(len(text)) if p[i] == r]
    out = [""] * len(text)
    for ch, i in zip(text, order): out[i] = ch
    return "".join(out)

def _col_order(key):
    k = [c for c in key.upper() if c.isalnum()]
    if not k: raise ValueError("The keyword must contain letters or digits.")
    return k, sorted(range(len(k)), key=lambda i: (k[i], i))
def columnar_encrypt(text, key):
    k, order = _col_order(key)
    n = len(k)
    text = text + "X" * (-len(text) % n)
    return "".join(text[c::n] for c in order)
def columnar_decrypt(text, key):
    k, order = _col_order(key)
    n = len(k)
    if len(text) % n:
        raise ValueError("Ciphertext length must be a multiple of the keyword length.")
    rows = len(text) // n
    cols = {}
    for idx, c in enumerate(order):
        cols[c] = text[idx * rows:(idx + 1) * rows]
    return "".join(cols[c][r] for r in range(rows) for c in range(n))
