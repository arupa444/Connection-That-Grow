import os
import json
import secrets
import hashlib
from typing import Optional, Dict

import pandas as pd
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import RedirectResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

# ---------- Config ----------
APP_NAME = "ConnectionDB"
EXCEL_FILE = "connections.xlsx"
USERS_FILE = "users.json"   # stores {"username": "salt$hex_hash", ...}
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
DEFAULT_ADMIN = {"username": "admin", "password": "secret123"}  # change after first run!

# ---------- App init ----------
app = FastAPI(title=APP_NAME)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ---------- Utilities: password hashing (PBKDF2) ----------
def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """
    Return a string salt_hex$hash_hex where hash = pbkdf2_hmac('sha256', password, salt, 200000)
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}${dk.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return secrets.compare_digest(candidate.hex(), hash_hex)
    except Exception:
        return False

# ---------- Users file management ----------
def ensure_users_file():
    if not os.path.exists(USERS_FILE):
        # create with one default admin user (please change password after first login)
        hashed = hash_password(DEFAULT_ADMIN["password"])
        with open(USERS_FILE, "w") as f:
            json.dump({DEFAULT_ADMIN["username"]: hashed}, f)
        print(f"Created {USERS_FILE} with default credentials: {DEFAULT_ADMIN['username']} / {DEFAULT_ADMIN['password']}")

def load_users() -> Dict[str, str]:
    ensure_users_file()
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users: Dict[str, str]):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

# ---------- Excel helpers ----------
def load_data():
    if not os.path.exists(EXCEL_FILE):
        df = pd.DataFrame(columns=["Name", "Company", "Connection Link", "Email", "Phone No.", "Role"])
        df.to_excel(EXCEL_FILE, index=False)
    return pd.read_excel(EXCEL_FILE)

def save_data(df):
    df.to_excel(EXCEL_FILE, index=False)

# ---------- Auth helpers ----------
def get_current_user(request: Request) -> Optional[str]:
    return request.session.get("user")

def require_login(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login?next=" + request.url.path, status_code=303)
    return None

# ---------- Routes ----------
@app.get("/", response_class=HTMLResponse)
def index(request: Request, q: Optional[str] = None):
    """
    Public listing (read-only). Add/Edit/Download require login.
    """
    df = load_data()
    if q:
        df = df[df.apply(lambda row: row.astype(str).str.contains(q, case=False, na=False).any(), axis=1)]
    records = df.to_dict(orient="records")
    return templates.TemplateResponse("index.html", {"request": request, "records": records, "query": q, "user": get_current_user(request)})

# ---------------- Login / logout ----------------
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: Optional[str] = "/"):
    return templates.TemplateResponse("login.html", {"request": request, "next": next, "error": None})

@app.post("/login")
def do_login(request: Request, username: str = Form(...), password: str = Form(...), next: Optional[str] = Form("/")):
    users = load_users()
    stored = users.get(username)
    if stored and verify_password(password, stored):
        request.session["user"] = username
        return RedirectResponse(next or "/", status_code=303)
    # invalid
    return templates.TemplateResponse("login.html", {"request": request, "next": next, "error": "Invalid credentials"})

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)

# ---------------- Add record (protected) ----------------
@app.get("/add")
def add_page(request: Request):
    if get_current_user(request) is None:
        return RedirectResponse("/login?next=/add", status_code=303)
    return templates.TemplateResponse("add.html", {"request": request, "user": get_current_user(request)})

@app.post("/add")
def add_record(request: Request,
               name: str = Form(...),
               company: str = Form(...),
               connection_link: str = Form(...),
               email: str = Form(...),
               phone: Optional[str] = Form(None),
               role: str = Form(...)):
    if get_current_user(request) is None:
        return RedirectResponse("/login?next=/add", status_code=303)
    # basic email validation
    if "@" not in email or "." not in email:
        return templates.TemplateResponse("add.html", {"request": request, "user": get_current_user(request), "error": "Invalid email"})
    df = load_data()
    new_row = {"Name": name, "Company": company, "Connection Link": connection_link,
               "Email": email, "Phone No.": phone, "Role": role}
    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    save_data(df)
    return RedirectResponse("/", status_code=303)

# ---------------- Update record (protected) ----------------
@app.get("/update/{idx}")
def update_page(request: Request, idx: int):
    if get_current_user(request) is None:
        return RedirectResponse(f"/login?next=/update/{idx}", status_code=303)
    df = load_data()
    if idx < 0 or idx >= len(df):
        return RedirectResponse("/", status_code=303)
    record = df.iloc[idx].to_dict()
    return templates.TemplateResponse("update.html", {"request": request, "record": record, "idx": idx, "user": get_current_user(request)})

@app.post("/update/{idx}")
def update_record(request: Request, idx: int,
                  name: str = Form(...),
                  company: str = Form(...),
                  connection_link: str = Form(...),
                  email: str = Form(...),
                  phone: Optional[str] = Form(None),
                  role: str = Form(...)):
    if get_current_user(request) is None:
        return RedirectResponse(f"/login?next=/update/{idx}", status_code=303)
    df = load_data()
    if 0 <= idx < len(df):
        df.loc[idx] = [name, company, connection_link, email, phone, role]
        save_data(df)
    return RedirectResponse("/", status_code=303)

# ---------------- Download (protected) ----------------
@app.get("/download")
def download_excel(request: Request):
    if get_current_user(request) is None:
        return RedirectResponse("/login?next=/download", status_code=303)
    return FileResponse(EXCEL_FILE, filename="connections.xlsx")

# ---------------- Admin: change password (optional) ----------------
@app.get("/change-password")
def change_password_page(request: Request):
    if get_current_user(request) is None:
        return RedirectResponse("/login?next=/change-password", status_code=303)
    return templates.TemplateResponse("change_password.html", {"request": request, "user": get_current_user(request), "error": None, "success": None})

@app.post("/change-password")
def change_password(request: Request, current: str = Form(...), new_password: str = Form(...), confirm: str = Form(...)):
    username = get_current_user(request)
    if username is None:
        return RedirectResponse("/login?next=/change-password", status_code=303)
    users = load_users()
    stored = users.get(username)
    if not stored or not verify_password(current, stored):
        return templates.TemplateResponse("change_password.html", {"request": request, "user": username, "error": "Current password incorrect", "success": None})
    if new_password != confirm:
        return templates.TemplateResponse("change_password.html", {"request": request, "user": username, "error": "Passwords do not match", "success": None})
    users[username] = hash_password(new_password)
    save_users(users)
    return templates.TemplateResponse("change_password.html", {"request": request, "user": username, "error": None, "success": "Password updated"})

# create default users file (if needed) at startup
ensure_users_file()
