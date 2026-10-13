# Classical Cryptography Toolkit - Google Colab version (redesigned UI)
# Cipher logic is unchanged. Only the interface is new. Paste into one Colab cell and run.
import random, string, math

A = string.ascii_uppercase

# ---------- Caesar ----------
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

# ---------- Monoalphabetic ----------
def validate_mono_key(key):
    return len(key) == 26 and set(key.upper()) == set(A)
def _mono(text, src, dst):
    table = {}
    for s, d in zip(src, dst):
        table[s] = d; table[s.lower()] = d.lower()
    return "".join(table.get(c, c) for c in text)
def mono_encrypt(t, key): return _mono(t, A, key.upper())
def mono_decrypt(t, key): return _mono(t, key.upper(), A)

# ---------- Playfair ----------
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

# ---------- Hill (2x2) ----------
HILL_KEY = [[3, 3], [2, 5]]
HILL_INV = [[15, 17], [20, 9]]   # inverse of HILL_KEY mod 26
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

# ---------- Vigenere ----------
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

# ---------- One-Time Pad ----------
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

# ---------- Rail Fence ----------
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

# ---------- Columnar Transposition ----------
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


# =====================  NEW GUI (Colab / ipywidgets)  =====================
import time, html
import ipywidgets as w
from IPython.display import display, HTML

# name -> (family, key placeholder, hint, short description)
CIPHERS = {
    "Caesar Cipher": ("Substitution", "e.g. 5",
        "Enter a whole-number shift.",
        "Shifts every letter by a fixed number of positions in the alphabet."),
    "Monoalphabetic Cipher": ("Substitution", "26-letter key",
        "Enter a 26-letter substitution key, or generate one.",
        "Replaces each letter using a fixed, shuffled alphabet."),
    "Playfair Cipher": ("Substitution", "e.g. MONARCHY",
        "Enter a keyword (J is treated as I).",
        "Encrypts letter pairs using a 5x5 key square."),
    "Hill Cipher": ("Substitution", "(fixed matrix)",
        "Uses the built-in key matrix [[3, 3], [2, 5]]. No key needed.",
        "Encrypts letter pairs with 2x2 matrix multiplication mod 26."),
    "Vigenere Cipher": ("Substitution", "e.g. KEY",
        "Enter a keyword.",
        "Applies a repeating keyword as a series of Caesar shifts."),
    "One-Time Pad": ("Substitution", "leave blank to auto-generate",
        "Encrypt: leave blank to generate a key. Decrypt: enter the same key.",
        "Uses a random key as long as the message. Unbreakable if the key is never reused."),
    "Rail Fence Cipher": ("Transposition", "e.g. 3",
        "Enter the number of rails.",
        "Writes the text in a zigzag across rails, then reads row by row."),
    "Columnar Transposition Cipher": ("Transposition", "e.g. ZEBRA",
        "Enter a keyword.",
        "Writes text in rows and reads the columns in keyword order."),
}

display(HTML("""<style>
.cg-root{background:#f4f6fb;border-radius:14px;padding:0;overflow:hidden;
  font-family:'Segoe UI',Roboto,Arial,sans-serif;max-width:960px;
  box-shadow:0 6px 24px rgba(20,30,60,.18);border:1px solid #d9deea}
.cg-head{background:linear-gradient(120deg,#1e1b4b 0%,#4338ca 55%,#0891b2 100%);padding:22px 26px;color:#fff}
.cg-title{font-size:22px;font-weight:700;letter-spacing:.5px}
.cg-sub{font-size:11.5pt;color:#c7d2fe;margin-top:4px}
.cg-body{padding:18px 22px}
.cg-card{background:#ffffff;border:1px solid #e2e6f0;border-radius:12px;padding:14px 16px;margin:0 0 14px 0;
  box-shadow:0 1px 3px rgba(20,30,60,.06)}
.cg-ct{font-weight:700;font-size:10.5pt;color:#312e81;margin-bottom:8px;letter-spacing:.3px}
.cg-lbl{color:#475569;font-size:10.5pt;min-width:105px;display:inline-block}
.cg-hint{color:#64748b;font-size:10pt;margin-top:2px}
.cg-info{background:#eef2ff;border-left:4px solid #6366f1;color:#312e81;padding:9px 12px;border-radius:6px;font-size:10.5pt;margin-top:8px}
.cg-badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:9pt;font-weight:600;margin-left:8px}
.cg-b-sub{background:#dbeafe;color:#1d4ed8}
.cg-b-tr{background:#fce7f3;color:#be185d}
.cg-count{color:#64748b;font-size:9.5pt;text-align:right;padding-right:4px}
.cg-ta textarea{font-family:'Fira Code',Consolas,monospace !important;font-size:11pt !important;
  background:#0f172a !important;color:#e2e8f0 !important;border:1px solid #334155 !important;
  border-radius:8px !important;padding:10px !important}
.cg-out textarea{color:#86efac !important}
.cg-in input{border-radius:8px !important;border:1px solid #94a3b8 !important}
.widget-button.cg-enc{background:#16a34a !important;color:#fff !important;font-weight:600;border-radius:8px}
.widget-button.cg-dec{background:#2563eb !important;color:#fff !important;font-weight:600;border-radius:8px}
.widget-button.cg-sec{background:#e2e8f0 !important;color:#1e293b !important;border-radius:8px}
.widget-button.cg-warn{background:#fee2e2 !important;color:#b91c1c !important;border-radius:8px}
.widget-button.cg-acc{background:#7c3aed !important;color:#fff !important;border-radius:8px}
.cg-st{padding:9px 14px;font-size:10.5pt;border-radius:8px;margin-top:2px}
.cg-st-info{background:#e0e7ff;color:#312e81}
.cg-st-ok{background:#dcfce7;color:#166534}
.cg-st-err{background:#fee2e2;color:#991b1b}
.cg-meta{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}
.cg-chip{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:8px;padding:4px 10px;font-size:9.5pt;color:#334155}
.cg-key{background:#fef9c3;border:1px solid #facc15;color:#713f12;border-radius:8px;padding:8px 12px;margin-top:8px;
  font-family:Consolas,monospace;font-size:10pt;word-break:break-all}
</style>"""))

def launch():
    names = list(CIPHERS)
    cipher_var = w.Dropdown(options=names, value=names[0], layout=w.Layout(width="280px"))
    badge = w.HTML()
    key_var = w.Text(layout=w.Layout(width="340px")); key_var.add_class("cg-in")
    key_hint = w.HTML()
    info = w.HTML()
    status = w.HTML()
    meta = w.HTML()
    in_count = w.HTML(); out_count = w.HTML()
    input_text = w.Textarea(placeholder="Type or paste your message here...",
                            layout=w.Layout(width="98%", height="130px")); input_text.add_class("cg-ta")
    output_text = w.Textarea(placeholder="Your result appears here...",
                             layout=w.Layout(width="98%", height="130px")); output_text.add_class("cg-ta"); output_text.add_class("cg-out")
    state = {"note": ""}

    def set_status(msg, kind="info"):
        status.value = f'<div class="cg-st cg-st-{kind}">{html.escape(msg)}</div>'

    def update_counts(_=None):
        in_count.value = f'<div class="cg-count">{len(input_text.value)} characters</div>'
        out_count.value = f'<div class="cg-count">{len(output_text.value)} characters</div>'
    input_text.observe(update_counts, names="value")
    output_text.observe(update_counts, names="value")

    def on_cipher_changed(_=None):
        fam, ph, hint, desc = CIPHERS[cipher_var.value]
        cls = "cg-b-sub" if fam == "Substitution" else "cg-b-tr"
        badge.value = f'<span class="cg-badge {cls}">{fam}</span>'
        key_var.placeholder = ph
        key_hint.value = f'<div class="cg-hint">{html.escape(hint)}</div>'
        info.value = f'<div class="cg-info"><b>{html.escape(cipher_var.value)}</b> &mdash; {html.escape(desc)}</div>'
        key_var.disabled = cipher_var.value == "Hill Cipher"
        if key_var.disabled: key_var.value = ""
    cipher_var.observe(on_cipher_changed, names="value")

    btn_gen = w.Button(description="Random Key", icon="random", tooltip="Generate a random substitution key",
                       layout=w.Layout(width="140px")); btn_gen.add_class("cg-acc")
    btn_clearkey = w.Button(description="Clear Key", icon="times", layout=w.Layout(width="120px")); btn_clearkey.add_class("cg-sec")
    btn_load = w.FileUpload(accept=".txt", multiple=False, description="Load .txt", layout=w.Layout(width="130px"))
    btn_clear_in = w.Button(description="Clear Input", icon="eraser", layout=w.Layout(width="130px")); btn_clear_in.add_class("cg-sec")
    btn_enc = w.Button(description="Encrypt", icon="lock", layout=w.Layout(width="150px", height="38px")); btn_enc.add_class("cg-enc")
    btn_dec = w.Button(description="Decrypt", icon="unlock", layout=w.Layout(width="150px", height="38px")); btn_dec.add_class("cg-dec")
    btn_swap = w.Button(description="Use Result as Input", icon="exchange", layout=w.Layout(width="190px")); btn_swap.add_class("cg-sec")
    btn_save = w.Button(description="Save Result", icon="download", layout=w.Layout(width="140px")); btn_save.add_class("cg-sec")
    btn_clear_out = w.Button(description="Clear Result", icon="trash", layout=w.Layout(width="140px")); btn_clear_out.add_class("cg-warn")

    def generate_substitution_key(_=None):
        letters = list(string.ascii_uppercase)
        random.SystemRandom().shuffle(letters)
        cipher_var.value = "Monoalphabetic Cipher"
        key_var.value = "".join(letters)
        set_status("A random substitution key was generated. Save it securely to decrypt later.", "ok")

    def show_error(msg):
        output_text.value = ""
        meta.value = ""
        state["note"] = ""
        set_status(msg, "err")

    def process(decrypt):
        text = input_text.value
        if not text:
            show_error("Please enter a message or load a text file."); return
        cipher = cipher_var.value
        key = key_var.value.strip()
        try:
            start = time.perf_counter()
            if cipher == "Caesar Cipher":
                if not key: raise ValueError("Please enter a numeric Caesar key.")
                shift = int(key)
                result = caesar_decrypt(text, shift) if decrypt else caesar_encrypt(text, shift)
            elif cipher == "Monoalphabetic Cipher":
                if not key: raise ValueError("Please enter or generate a substitution key.")
                key = key.upper()
                if not validate_mono_key(key):
                    raise ValueError("The substitution key must contain all 26 English letters exactly once.")
                result = mono_decrypt(text, key) if decrypt else mono_encrypt(text, key)
            elif cipher == "Playfair Cipher":
                if not key: raise ValueError("Please enter a Playfair keyword.")
                result = playfair_transform(text, key, decrypt)
            elif cipher == "Hill Cipher":
                result = hill_decrypt(text) if decrypt else hill_encrypt(text)
            elif cipher == "Vigenere Cipher":
                if not key: raise ValueError("Please enter a Vigenere keyword.")
                result = vigenere_transform(text, key, decrypt)
            elif cipher == "One-Time Pad":
                if decrypt:
                    if not key: raise ValueError("Enter the One-Time Pad key used during encryption.")
                    result = otp_transform(text, key, True)
                else:
                    if not key:
                        key = otp_generate_key(text); key_var.value = key
                    result = otp_transform(text, key, False)
            elif cipher == "Rail Fence Cipher":
                if not key: raise ValueError("Please enter the number of rails.")
                rails = int(key)
                if rails < 1: raise ValueError("The number of rails must be at least 1.")
                result = rail_fence_decrypt(text, rails) if decrypt else rail_fence_encrypt(text, rails)
            elif cipher == "Columnar Transposition Cipher":
                if not key: raise ValueError("Please enter a Columnar Transposition keyword.")
                result = columnar_decrypt(text, key) if decrypt else columnar_encrypt(text, key)
            else:
                raise ValueError("Please select a valid cipher.")
            elapsed = time.perf_counter() - start
            action = "Decrypted" if decrypt else "Encrypted"
            output_text.value = result

            chips = (f'<span class="cg-chip">Action: <b>{action}</b></span>'
                     f'<span class="cg-chip">Cipher: <b>{html.escape(cipher)}</b></span>'
                     f'<span class="cg-chip">Execution time: <b>{elapsed:.8f} s</b></span>')
            extra, note = "", ""
            if cipher == "One-Time Pad" and not decrypt:
                extra = ('<div class="cg-key"><b>IMPORTANT &mdash; save this One-Time Pad key for decryption:</b><br>'
                         f'{html.escape(key)}</div>')
                note = f"One-Time Pad key: {key}"
            if cipher == "Hill Cipher":
                extra += '<div class="cg-hint">Note: Hill Cipher uses the fixed matrix [[3, 3], [2, 5]].</div>'
            state["note"] = f"{action} with {cipher} in {elapsed:.8f} s" + (f"\n{note}" if note else "")
            meta.value = f'<div class="cg-meta">{chips}</div>{extra}'
            set_status(f"{action} successfully using {cipher}.", "ok")
        except (ValueError, TypeError) as e:
            show_error(str(e))
        except Exception as e:
            show_error(f"Unexpected error: {e}")

    def load_file(change):
        if not btn_load.value: return
        f = btn_load.value[0] if isinstance(btn_load.value, (tuple, list)) else list(btn_load.value.values())[0]
        content = f["content"] if isinstance(f, dict) else f.content
        name = f["name"] if isinstance(f, dict) else f.name
        input_text.value = bytes(content).decode("utf-8", errors="replace")
        set_status(f"Loaded file: {name}", "ok")

    def save_result(_=None):
        contents = output_text.value
        if not contents.strip():
            set_status("There is no result to save yet. Encrypt or decrypt first.", "err"); return
        with open("encrypted_result.txt", "w", encoding="utf-8") as fh:
            fh.write(contents + ("\n\n" + state["note"] if state["note"] else ""))
        try:
            from google.colab import files
            files.download("encrypted_result.txt")
        except ImportError:
            pass
        set_status("Result saved to: encrypted_result.txt", "ok")

    def use_as_input(_=None):
        if not output_text.value.strip():
            set_status("There is no result to move yet.", "err"); return
        input_text.value = output_text.value
        output_text.value = ""; meta.value = ""
        set_status("Result moved to the input box. Choose Encrypt or Decrypt to continue.", "info")

    def clear_input(_=None):
        input_text.value = ""; set_status("Input cleared.")
    def clear_output(_=None):
        output_text.value = ""; meta.value = ""; state["note"] = ""; set_status("Result cleared.")

    btn_gen.on_click(generate_substitution_key)
    btn_clearkey.on_click(lambda _: setattr(key_var, "value", ""))
    btn_clear_in.on_click(clear_input)
    btn_clear_out.on_click(clear_output)
    btn_enc.on_click(lambda _: process(False))
    btn_dec.on_click(lambda _: process(True))
    btn_swap.on_click(use_as_input)
    btn_save.on_click(save_result)
    btn_load.observe(load_file, names="value")

    def lbl(t): return w.HTML(f'<span class="cg-lbl">{t}</span>')
    def card(title, children):
        box = w.VBox([w.HTML(f'<div class="cg-ct">{title}</div>')] + children); box.add_class("cg-card"); return box

    header = w.HTML('<div class="cg-head"><div class="cg-title">&#128272; CLASSICAL CRYPTOGRAPHY TOOLKIT</div>'
                    '<div class="cg-sub">Encrypt &bull; Decrypt &bull; Load files &bull; Save results &bull; Measure execution time</div></div>')

    settings = card("1 &nbsp;CIPHER SETTINGS", [
        w.HBox([lbl("Cipher"), cipher_var, badge], layout=w.Layout(align_items="center")),
        info,
        w.HBox([lbl("Key / Keyword"), key_var, w.HTML("&nbsp;&nbsp;"), btn_gen, w.HTML("&nbsp;"), btn_clearkey],
               layout=w.Layout(align_items="center", margin="8px 0 0 0")),
        key_hint,
    ])
    message = card("2 &nbsp;INPUT MESSAGE", [
        input_text, in_count,
        w.HBox([btn_load, w.HTML("&nbsp;"), btn_clear_in]),
    ])
    actions = w.HBox([btn_enc, w.HTML("&nbsp;&nbsp;"), btn_dec], layout=w.Layout(margin="0 0 14px 0"))
    result = card("3 &nbsp;OUTPUT RESULT", [
        output_text, out_count, meta,
        w.HBox([btn_swap, w.HTML("&nbsp;"), btn_save, w.HTML("&nbsp;"), btn_clear_out], layout=w.Layout(margin="10px 0 0 0")),
    ])
    body = w.VBox([settings, message, actions, result, status]); body.add_class("cg-body")
    root = w.VBox([header, body]); root.add_class("cg-root")

    on_cipher_changed(); update_counts()
    set_status("Ready. Enter a message and choose a cipher.")
    display(root)

launch()
