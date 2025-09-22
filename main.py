# main.py — WSL-safe Secure File API
# Requires: fastapi, uvicorn, python-dotenv, passlib[bcrypt]
import os
import subprocess
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from passlib.context import CryptContext
from pathlib import Path

load_dotenv()

# --- config (set in .env using WSL paths, e.g. /mnt/d/...) ---
HASH_FILE_PATH   = os.getenv("HASH_FILE_PATH")       # e.g. /mnt/d/Auth/secure.hash
SECURE_DIR       = os.getenv("SECURE_FILE_PATH")     # e.g. /mnt/g/SecureStuff  (folder)
USB_DRIVE        = os.getenv("USB_DRIVE", "D:")
EXPECTED_VOLUME_ID = (os.getenv("EXPECTED_VOLUME_ID") or "").strip()

# --- crypto context (bcrypt-sha256 only) ---
pwd_context = CryptContext(
    schemes=["bcrypt_sha256"],
    bcrypt_sha256__rounds=12,
    deprecated="auto",
)

app = FastAPI(title="SecureStuff API")

# --- helpers ---
def norm_id(s: str) -> str:
    return "".join(ch for ch in (s or "").upper() if ch.isalnum())

def get_volume_serial(drive: str) -> str:
    """
    Use Windows 'vol D:' called from WSL to fetch '78FD-3BDE' (whatever format).
    """
    try:
        out = subprocess.check_output(["cmd.exe", "/c", "vol", drive], text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to read volume serial for {drive}: {e.output}")
    for line in out.splitlines():
        line = line.strip()
        if "Serial Number is" in line:
            return line.rsplit(" ", 1)[-1].strip()
    raise RuntimeError(f"Could not parse volume serial from output: {out!r}")

def read_hash() -> str:
    if not HASH_FILE_PATH:
        raise RuntimeError("HASH_FILE_PATH not configured.")
    try:
        data = open(HASH_FILE_PATH, "r", encoding="utf-8").read().strip()
    except FileNotFoundError:
        raise RuntimeError(f"Hash file not found: {HASH_FILE_PATH}")
    if not data or not data.startswith("$"):
        raise RuntimeError("Hash file content invalid or empty.")
    return data

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return pwd_context.verify(password, stored_hash)
    except Exception:
        return False

def resolve_and_check_path(rel_path: str) -> Path:
    """
    Resolve a user-supplied relative path inside SECURE_DIR.
    Prevents traversal outside SECURE_DIR.
    """
    if not SECURE_DIR:
        raise HTTPException(status_code=500, detail="SECURE_DIR not configured.")
    base = Path(SECURE_DIR).resolve()
    # empty path => list base
    p = (base / rel_path).resolve()
    if not str(p).startswith(str(base)):
        raise HTTPException(status_code=403, detail="Access denied.")
    return p

# --- startup checks ---
STORED_HASH: Optional[str] = None

@app.on_event("startup")
def startup_checks():
    global STORED_HASH
    # ensure secure dir path is a directory (create if not exists)
    if SECURE_DIR:
        Path(SECURE_DIR).mkdir(parents=True, exist_ok=True)

    # read hash
    STORED_HASH = read_hash()  # will raise RuntimeError (and stop uvicorn) if missing/invalid

    # check USB serial if EXPECTED_VOLUME_ID is set
    if EXPECTED_VOLUME_ID:
        actual = get_volume_serial(USB_DRIVE)
        if norm_id(actual) != norm_id(EXPECTED_VOLUME_ID):
            raise RuntimeError(f"USB volume mismatch. Expected [{EXPECTED_VOLUME_ID}] got [{actual}].")

# --- API models ---
class LoginReq(BaseModel):
    username: Optional[str] = None
    password: str

class ReadReq(BaseModel):
    password: str
    path: Optional[str] = ""   # relative path under SECURE_DIR; empty => list root

# --- endpoints ---
@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/login")
def login(req: LoginReq):
    if not STORED_HASH:
        raise HTTPException(status_code=500, detail="Server misconfigured (no stored hash).")
    if not verify_password(req.password, STORED_HASH):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"status": "ok"}

@app.post("/read")
def read(req: ReadReq):
    """
    Verify password then return file contents or directory listing.
    - If path is directory (or empty), return list of entries.
    - If path is file, return raw text content.
    """
    if not STORED_HASH:
        raise HTTPException(status_code=500, detail="Server misconfigured (no stored hash).")

    if not verify_password(req.password, STORED_HASH):
        raise HTTPException(status_code=401, detail="Unauthorized")

    p = resolve_and_check_path(req.path or "")
    if not p.exists():
        raise HTTPException(status_code=404, detail="Not found")

    if p.is_dir():
        entries = []
        for child in sorted(p.iterdir()):
            entries.append({
                "name": child.name,
                "is_dir": child.is_dir(),
                "size": child.stat().st_size
            })
        return {"path": str(p), "type": "directory", "entries": entries}
    else:
        # serve file text content (binary files are returned base64-safe in future if needed)
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=415, detail="File is not UTF-8 text")
        return {"path": str(p), "type": "file", "content": text}
