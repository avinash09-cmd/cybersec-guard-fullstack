"""
password_tool.py
-----------------
Password Strength Checker + bcrypt-backed Encrypted Vault.

Two different cryptographic jobs, done with the right tool for each:

1. AUTHENTICATING the vault's master password → bcrypt.
   bcrypt is a one-way, salted, adaptive hash — correct choice for
   "does this password match?" without ever needing to recover the
   original password. The bcrypt hash is what's stored in MySQL.

2. ENCRYPTING/DECRYPTING the stored site passwords → PBKDF2 + Fernet (AES).
   Vault entries must be *recoverable* (you need to read the password
   back out), which a one-way hash like bcrypt cannot do. So a separate
   AES key is derived from the same master password via PBKDF2-HMAC-SHA256,
   and that key encrypts/decrypts each entry with Fernet.

   This two-key pattern (hash for auth, derived key for encryption) is
   standard practice — see e.g. how password managers like Bitwarden
   separate the "master password verification" step from the "vault
   encryption key" step.
"""

import base64
import math
import re
import string

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from database import get_session, VaultMaster, VaultEntry

PBKDF2_ITERATIONS = 390_000

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "iloveyou", "admin", "welcome",
    "monkey", "letmein", "dragon", "football", "123123", "000000",
}


# ---------------------------------------------------------------------------
# Strength checker (pure function, no DB/crypto dependency)
# ---------------------------------------------------------------------------

def estimate_entropy(password):
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"[0-9]", password): pool += 10
    if re.search(r"[^a-zA-Z0-9]", password): pool += 32
    return len(password) * math.log2(pool) if pool else 0


def has_sequential_chars(password, run_length=3):
    lowered = password.lower()
    for seq in [string.ascii_lowercase, string.digits, "qwertyuiop", "asdfghjkl", "zxcvbnm"]:
        for i in range(len(seq) - run_length + 1):
            if seq[i:i + run_length] in lowered:
                return True
    return False


def has_repeated_chars(password, run_length=3):
    return bool(re.search(r"(.)\1{" + str(run_length - 1) + ",}", password))


def crack_time_estimate(entropy_bits):
    guesses = 2 ** entropy_bits
    seconds = guesses / 1e10
    if seconds < 1:
        return "instantly"
    for unit, secs in [("centuries", 3.15e9), ("years", 3.15e7), ("days", 86400),
                        ("hours", 3600), ("minutes", 60), ("seconds", 1)]:
        if seconds >= secs:
            return f"~{seconds/secs:,.1f} {unit}"
    return f"~{seconds:.1f} seconds"


def check_password_strength(password):
    issues, score = [], 0
    if len(password) < 8:
        issues.append("Too short (use at least 12 characters).")
    elif len(password) < 12:
        issues.append("Reasonable length, but 12+ is stronger."); score += 1
    else:
        score += 2

    classes = sum([bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^a-zA-Z0-9]")])
    score += classes - 1
    if classes < 3:
        issues.append("Add more character variety (upper/lower/digits/symbols).")

    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is one of the most common leaked passwords — never use it."); score = 0
    if has_sequential_chars(password):
        issues.append("Contains a sequential pattern (e.g. 'abc', '123', 'qwerty')."); score -= 1
    if has_repeated_chars(password):
        issues.append("Contains repeated characters (e.g. 'aaa', '111')."); score -= 1

    score = max(0, min(score, 5))
    entropy = estimate_entropy(password)
    labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]

    return {
        "score": score, "label": labels[score],
        "entropy_bits": round(entropy, 1),
        "estimated_crack_time": crack_time_estimate(entropy),
        "issues": issues or ["No major issues found."],
    }


# ---------------------------------------------------------------------------
# bcrypt master-password auth
# ---------------------------------------------------------------------------

def _derive_fernet_key(master_password, salt_b64):
    salt = base64.b64decode(salt_b64)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def vault_exists():
    db = get_session()
    try:
        return db.query(VaultMaster).first() is not None
    finally:
        db.close()


def create_vault(master_password):
    """First-time setup: bcrypt-hash the master password and store a PBKDF2 salt."""
    import os
    bcrypt_hash = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt()).decode()
    pbkdf2_salt = base64.b64encode(os.urandom(16)).decode()

    db = get_session()
    try:
        db.add(VaultMaster(bcrypt_hash=bcrypt_hash, pbkdf2_salt=pbkdf2_salt))
        db.commit()
    finally:
        db.close()


def unlock_vault(master_password):
    """Verifies the master password against the stored bcrypt hash.
    Returns the derived Fernet key (for this request only — never stored) or None."""
    db = get_session()
    try:
        row = db.query(VaultMaster).first()
        if row is None:
            return None
        if not bcrypt.checkpw(master_password.encode(), row.bcrypt_hash.encode()):
            return None
        return _derive_fernet_key(master_password, row.pbkdf2_salt)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Vault entries (MySQL-backed, Fernet-encrypted)
# ---------------------------------------------------------------------------

def add_entry(fernet_key, site, username, password):
    f = Fernet(fernet_key)
    encrypted = f.encrypt(password.encode()).decode()
    db = get_session()
    try:
        db.add(VaultEntry(site=site, username=username, encrypted_password=encrypted))
        db.commit()
    finally:
        db.close()


def list_entries():
    """Returns site/username only — passwords stay encrypted until explicitly decrypted."""
    db = get_session()
    try:
        rows = db.query(VaultEntry).all()
        return [{"id": r.id, "site": r.site, "username": r.username} for r in rows]
    finally:
        db.close()


def reveal_entry(fernet_key, entry_id):
    f = Fernet(fernet_key)
    db = get_session()
    try:
        row = db.query(VaultEntry).filter_by(id=entry_id).first()
        if row is None:
            return None
        try:
            decrypted = f.decrypt(row.encrypted_password.encode()).decode()
        except InvalidToken:
            return None
        return {"site": row.site, "username": row.username, "password": decrypted}
    finally:
        db.close()


def delete_entry(entry_id):
    db = get_session()
    try:
        row = db.query(VaultEntry).filter_by(id=entry_id).first()
        if row:
            db.delete(row)
            db.commit()
            return True
        return False
    finally:
        db.close()
