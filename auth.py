# auth.py — WSL-safe; setup-if-missing then verify; password prompt; no BitLocker
import os, sys, time, subprocess, getpass, tempfile
from dotenv import load_dotenv
from passlib.context import CryptContext

load_dotenv()
HASH_FILE_PATH     = os.getenv("HASH_FILE_PATH")          # e.g., /mnt/d/Auth/secure.hash
SECURE_FILE_PATH   = os.getenv("SECURE_FILE_PATH")        # e.g., /mnt/g/SecureStuff/secure.txt
USB_DRIVE          = os.getenv("USB_DRIVE", "D:")
EXPECTED_VOLUME_ID = (os.getenv("EXPECTED_VOLUME_ID") or "").strip()

pwd_context = CryptContext(
    schemes=["bcrypt_sha256"],          # stick to bcrypt-sha256
    bcrypt_sha256__rounds=12,
    deprecated="auto",
)

def die(msg: str, code: int = 1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)

def norm_id(s: str) -> str:
    # Remove non-alnum; upper-case (handles '78FD3BDE' vs '78FD-3BDE')
    return "".join(ch for ch in s.upper() if ch.isalnum())

def get_volume_serial(drive: str) -> str:
    """Call Windows 'vol D:' via cmd.exe from WSL and parse the serial like 'ABCD-EF12'."""
    try:
        out = subprocess.check_output(
            ["cmd.exe", "/c", "vol", drive],
            text=True, stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        die(f"Failed to read volume serial for {drive}: {e.output}")
    for line in out.splitlines():
        line = line.strip()
        if "Serial Number is" in line:
            return line.rsplit(" ", 1)[-1].strip()
    die(f"Could not parse volume serial from: {out!r}")

def ensure_dirs():
    if not HASH_FILE_PATH:
        die("HASH_FILE_PATH not set")
    hdir = os.path.dirname(HASH_FILE_PATH)
    if hdir:
        os.makedirs(hdir, exist_ok=True)
    if SECURE_FILE_PATH:
        sdir = os.path.dirname(SECURE_FILE_PATH)
        if sdir:
            os.makedirs(sdir, exist_ok=True)

def usb_guard():
    if EXPECTED_VOLUME_ID:
        actual = get_volume_serial(USB_DRIVE)
        if norm_id(actual) != norm_id(EXPECTED_VOLUME_ID):
            die(f"USB volume mismatch. Expected [{EXPECTED_VOLUME_ID}] got [{actual}].")

def read_existing_hash() -> str | None:
    try:
        data = open(HASH_FILE_PATH, "r", encoding="utf-8").read().strip()
    except FileNotFoundError:
        return None
    if not data or not data.startswith("$"):
        return None
    return data

def write_hash_atomically(hashed: str):
    # Write to a temp file in the same dir, then rename
    d = os.path.dirname(HASH_FILE_PATH) or "."
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=d, delete=False) as tmp:
        tmp.write(hashed + "\n")
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    os.replace(tmp_path, HASH_FILE_PATH)
    try:
        # On drvfs this is best-effort, but harmless
        os.chmod(HASH_FILE_PATH, 0o600)
    except PermissionError:
        pass

def password_policy(pw: str) -> str | None:
    # Minimal sane policy — tune as you like
    if len(pw) < 8:
        return "Password must be at least 8 characters."
    return None

def setup_flow():
    print("No valid hash found. Setting an initial password.")
    while True:
        pw1 = getpass.getpass("New password: ")
        err = password_policy(pw1)
        if err:
            print(f"ERROR: {err}")
            continue
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("ERROR: Passwords do not match. Try again.")
            continue
        hashed = pwd_context.hash(pw1)
        write_hash_atomically(hashed)
        print(f"Wrote bcrypt-sha256 hash to {HASH_FILE_PATH}")
        break

def verify_flow(stored_hash: str):
    pw = getpass.getpass("Enter password: ")
    ok = pwd_context.verify(pw, stored_hash)
    time.sleep(0.06)  # small jitter to flatten timing
    if not ok:
        die("Invalid credentials.", 2)
    print("Auth OK")
    if SECURE_FILE_PATH:
        with open(SECURE_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(f"access {time.time()}\n")

def main():
    ensure_dirs()
    usb_guard()
    stored = read_existing_hash()
    if stored is None:
        setup_flow()
        stored = read_existing_hash()
        if stored is None:
            die("Failed to write hash file.")
    verify_flow(stored)

if __name__ == "__main__":
    main()
