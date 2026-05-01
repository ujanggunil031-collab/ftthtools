"""
FTTH Tools — Streamlit Application
Supabase backend · multi-user auth · quota system · activity logging
"""

# ─── MUST be first Streamlit call ─────────────────────────────────────────────
import streamlit as st

st.set_page_config(
    page_title="FTTH Tools",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Standard library ─────────────────────────────────────────────────────────
import io
import re
import zipfile
import datetime
import bcrypt
import logging
from xml.dom import minidom

# ─── Third-party ──────────────────────────────────────────────────────────────
import openpyxl
import math
from supabase import create_client, Client

# ─── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ftth_tools")

# ══════════════════════════════════════════════════════════════════════════════
# 1.  SUPABASE CLIENT
# ══════════════════════════════════════════════════════════════════════════════

@st.cache_resource(show_spinner=False)
def get_supabase() -> Client:
    url = st.secrets["SUPABASE_URL"]
    key = st.secrets["SUPABASE_KEY"]
    return create_client(url, key)


def supabase() -> Client:
    """Shortcut so call-sites stay tidy."""
    return get_supabase()


# ══════════════════════════════════════════════════════════════════════════════
# 2.  PASSWORD HELPERS  (bcrypt — compatible with Supabase pgcrypto hashes)
# ══════════════════════════════════════════════════════════════════════════════

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plain password against a bcrypt hash stored in DB.
    Handles both $2a$ (PostgreSQL pgcrypto) and $2b$ (Python bcrypt) prefixes.
    """
    try:
        # Normalize $2a$ → $2b$ so Python's bcrypt library accepts it
        normalized = stored_hash.replace("$2a$", "$2b$", 1) if stored_hash.startswith("$2a$") else stored_hash
        return bcrypt.checkpw(password.encode("utf-8"), normalized.encode("utf-8"))
    except Exception:
        return False


def hash_for_storage(password: str) -> str:
    """Returns a bcrypt hash string for DB storage."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# 3.  DB HELPERS — users
# ══════════════════════════════════════════════════════════════════════════════

def get_user_by_username(username: str) -> dict | None:
    try:
        res = supabase().table("users").select("*").eq("username", username).execute()
        return res.data[0] if res.data else None
    except Exception as e:
        logger.error("get_user_by_username error: %s", e)
        return None


def get_user_by_id(user_id: str) -> dict | None:
    try:
        res = supabase().table("users").select("*").eq("id", user_id).execute()
        return res.data[0] if res.data else None
    except Exception as e:
        logger.error("get_user_by_id error: %s", e)
        return None


def get_all_users() -> list[dict]:
    try:
        res = supabase().table("users").select("*").order("created_at", desc=True).execute()
        return res.data or []
    except Exception as e:
        logger.error("get_all_users error: %s", e)
        return []


def register_user(username: str, email: str, password: str) -> tuple[bool, str]:
    """Returns (success, message)."""
    if not username or not email or not password:
        return False, "Semua field wajib diisi."
    if len(password) < 6:
        return False, "Password minimal 6 karakter."

    # Check duplicate
    try:
        dup_u = supabase().table("users").select("id").eq("username", username).execute()
        if dup_u.data:
            return False, "Username sudah digunakan."
        dup_e = supabase().table("users").select("id").eq("email", email).execute()
        if dup_e.data:
            return False, "Email sudah terdaftar."
    except Exception as e:
        logger.error("register_user dup-check error: %s", e)
        return False, f"Database error: {e}"

    pw_hash = hash_for_storage(password)
    try:
        supabase().table("users").insert({
            "username": username,
            "email": email,
            "password_hash": pw_hash,
            "role": "user",
            "quota_remaining": 2,
            "quota_total": 2,
            "is_active": True,
        }).execute()
        logger.info("New user registered: %s", username)
        return True, "Registrasi berhasil! Silakan login."
    except Exception as e:
        logger.error("register_user insert error: %s", e)
        return False, f"Gagal registrasi: {e}"


def update_user_quota(user_id: str, new_quota: int) -> bool:
    try:
        supabase().table("users").update({"quota_remaining": new_quota}).eq("id", user_id).execute()
        return True
    except Exception as e:
        logger.error("update_user_quota error: %s", e)
        return False


def deduct_quota(user_id: str) -> bool:
    """Atomically deduct 1 from quota_remaining. Returns False if quota is 0."""
    user = get_user_by_id(user_id)
    if not user or user["quota_remaining"] <= 0:
        return False
    return update_user_quota(user_id, user["quota_remaining"] - 1)


def set_user_active(user_id: str, is_active: bool) -> bool:
    try:
        supabase().table("users").update({"is_active": is_active}).eq("id", user_id).execute()
        return True
    except Exception as e:
        logger.error("set_user_active error: %s", e)
        return False


def delete_user(user_id: str) -> bool:
    try:
        supabase().table("users").delete().eq("id", user_id).execute()
        return True
    except Exception as e:
        logger.error("delete_user error: %s", e)
        return False


def add_quota(user_id: str, amount: int) -> bool:
    user = get_user_by_id(user_id)
    if not user:
        return False
    new_q = user["quota_remaining"] + amount
    new_total = user["quota_total"] + amount
    try:
        supabase().table("users").update({
            "quota_remaining": new_q,
            "quota_total": new_total,
        }).eq("id", user_id).execute()
        return True
    except Exception as e:
        logger.error("add_quota error: %s", e)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 4.  DB HELPERS — activity logs
# ══════════════════════════════════════════════════════════════════════════════

def write_log(
    username: str,
    action: str,
    tool: str,
    status: str = "success",
    file_name: str | None = None,
    details: str | None = None,
    user_id: str | None = None,
) -> None:
    try:
        supabase().table("activity_logs").insert({
            "user_id": user_id,
            "username": username,
            "action": action,
            "tool": tool,
            "file_name": file_name,
            "status": status,
            "details": details,
        }).execute()
        logger.info("[LOG] user=%s action=%s tool=%s status=%s", username, action, tool, status)
    except Exception as e:
        logger.error("write_log error: %s", e)


def get_recent_logs(limit: int = 100) -> list[dict]:
    try:
        res = (
            supabase()
            .table("activity_logs")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return res.data or []
    except Exception as e:
        logger.error("get_recent_logs error: %s", e)
        return []


# ══════════════════════════════════════════════════════════════════════════════
# 5.  SESSION MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def init_session():
    defaults = {
        "authenticated": False,
        "user": None,          # full user dict from DB
        "auth_tab": "login",   # "login" | "register"
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def login_user(user: dict):
    st.session_state.authenticated = True
    st.session_state.user = user
    logger.info("User logged in: %s", user["username"])


def logout_user():
    username = st.session_state.user["username"] if st.session_state.user else "unknown"
    write_log(
        username=username,
        action="Logout",
        tool="system",
        status="info",
        user_id=st.session_state.user["id"] if st.session_state.user else None,
    )
    st.session_state.authenticated = False
    st.session_state.user = None
    logger.info("User logged out: %s", username)


def refresh_current_user():
    """Re-fetch the current user's data from DB (to reflect quota changes etc)."""
    if st.session_state.user:
        updated = get_user_by_id(st.session_state.user["id"])
        if updated:
            st.session_state.user = updated


# ══════════════════════════════════════════════════════════════════════════════
# 6.  CINEMATIC HERO CSS  (adapted from document.md palette)
# ══════════════════════════════════════════════════════════════════════════════

HERO_CSS = """
<style>
  /* ── Global resets inside Streamlit ─────────────────────── */
  #MainMenu, footer, header { visibility: hidden; }
  .block-container { padding-top: 0 !important; }

  /* ── Design tokens ───────────────────────────────────────── */
  :root {
    --navy:   #050914;
    --blue:   #2563eb;
    --blue-l: #3b82f6;
    --slate:  #1e2a3a;
    --white:  #f8fafc;
    --muted:  #94a3b8;
    --card-bg: linear-gradient(145deg, #162c6d 0%, #0a101d 100%);
  }

  /* ── Scrollbar ────────────────────────────────────────────── */
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: var(--navy); }
  ::-webkit-scrollbar-thumb { background: var(--slate); border-radius: 3px; }

  /* ── Streamlit body override ─────────────────────────────── */
  .stApp { background: var(--navy) !important; color: var(--white) !important; }

  /* ── Hero section ─────────────────────────────────────────── */
  .ftth-hero {
    position: relative;
    min-height: 92vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    padding: 4rem 1.5rem 3rem;
    overflow: hidden;
  }

  /* Grid background */
  .ftth-hero::before {
    content: "";
    position: absolute; inset: 0;
    background-size: 60px 60px;
    background-image:
      linear-gradient(to right, rgba(255,255,255,0.04) 1px, transparent 1px),
      linear-gradient(to bottom, rgba(255,255,255,0.04) 1px, transparent 1px);
    mask-image: radial-gradient(ellipse at center, black 0%, transparent 70%);
    -webkit-mask-image: radial-gradient(ellipse at center, black 0%, transparent 70%);
    pointer-events: none;
  }

  /* Blue glow behind title */
  .ftth-hero::after {
    content: "";
    position: absolute;
    top: 20%; left: 50%;
    transform: translate(-50%, -50%);
    width: 600px; height: 600px;
    background: radial-gradient(circle, rgba(37,99,235,0.18) 0%, transparent 70%);
    pointer-events: none;
  }

  .hero-eyebrow {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(37,99,235,0.15);
    border: 1px solid rgba(37,99,235,0.35);
    border-radius: 999px;
    padding: 6px 16px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--blue-l);
    margin-bottom: 1.5rem;
    position: relative; z-index: 1;
    animation: fadeUp 0.6s ease both;
  }

  .hero-eyebrow .dot {
    width: 6px; height: 6px;
    background: var(--blue-l);
    border-radius: 50%;
    animation: pulse 2s infinite;
  }

  .hero-title {
    font-size: clamp(2.2rem, 6vw, 4.5rem);
    font-weight: 900;
    line-height: 1.1;
    letter-spacing: -0.03em;
    color: var(--white);
    margin-bottom: 1.25rem;
    position: relative; z-index: 1;
    animation: fadeUp 0.7s 0.1s ease both;
  }

  .hero-title .accent {
    background: linear-gradient(135deg, #60a5fa 0%, #2563eb 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .hero-sub {
    font-size: clamp(1rem, 2vw, 1.2rem);
    line-height: 1.65;
    color: var(--muted);
    max-width: 640px;
    margin: 0 auto 2.5rem;
    position: relative; z-index: 1;
    animation: fadeUp 0.8s 0.2s ease both;
  }

  /* Stats row */
  .hero-stats {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    justify-content: center;
    margin-bottom: 3rem;
    position: relative; z-index: 1;
    animation: fadeUp 0.9s 0.3s ease both;
  }

  .stat-badge {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 0.9rem 1.4rem;
    text-align: center;
    backdrop-filter: blur(12px);
    min-width: 110px;
  }
  .stat-badge .val {
    font-size: 1.5rem;
    font-weight: 800;
    color: var(--white);
    line-height: 1;
  }
  .stat-badge .lbl {
    font-size: 0.7rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 4px;
  }

  /* Feature cards */
  .feature-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 1rem;
    max-width: 900px;
    width: 100%;
    margin: 0 auto;
    position: relative; z-index: 1;
    animation: fadeUp 1s 0.4s ease both;
  }

  .feature-card {
    background: linear-gradient(145deg, rgba(22,44,109,0.6) 0%, rgba(10,16,29,0.8) 100%);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 16px;
    padding: 1.4rem;
    display: flex;
    align-items: flex-start;
    gap: 12px;
    backdrop-filter: blur(12px);
    transition: transform 0.2s ease, border-color 0.2s ease;
  }

  .feature-card:hover {
    transform: translateY(-3px);
    border-color: rgba(37,99,235,0.4);
  }

  .feature-icon {
    width: 38px; height: 38px;
    background: rgba(37,99,235,0.2);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.1rem;
    flex-shrink: 0;
  }

  .feature-card h4 {
    font-size: 0.9rem;
    font-weight: 700;
    color: var(--white);
    margin: 0 0 4px;
  }

  .feature-card p {
    font-size: 0.78rem;
    color: var(--muted);
    margin: 0;
    line-height: 1.5;
  }

  /* ── Navbar ───────────────────────────────────────────────── */
  .ftth-navbar {
    position: sticky;
    top: 0;
    z-index: 999;
    background: rgba(5,9,20,0.85);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-bottom: 1px solid rgba(255,255,255,0.06);
    padding: 0.75rem 1.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
  }

  .navbar-brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 1.1rem;
    font-weight: 800;
    color: var(--white);
    text-decoration: none;
    letter-spacing: -0.02em;
  }

  .navbar-brand .logo-box {
    width: 32px; height: 32px;
    background: var(--blue);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1rem;
  }

  .navbar-right {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }

  .nav-user-pill {
    display: flex;
    align-items: center;
    gap: 8px;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 999px;
    padding: 5px 12px 5px 6px;
    font-size: 0.8rem;
    color: var(--white);
  }

  .nav-user-pill .avatar {
    width: 24px; height: 24px;
    background: var(--blue);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.65rem;
    font-weight: 700;
    color: white;
    text-transform: uppercase;
    flex-shrink: 0;
  }

  .nav-quota-badge {
    background: rgba(37,99,235,0.2);
    border: 1px solid rgba(37,99,235,0.4);
    color: #93c5fd;
    border-radius: 999px;
    padding: 3px 10px;
    font-size: 0.72rem;
    font-weight: 600;
  }

  .nav-role-badge {
    background: rgba(234,179,8,0.15);
    border: 1px solid rgba(234,179,8,0.3);
    color: #fcd34d;
    border-radius: 999px;
    padding: 3px 10px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  /* ── Sidebar override ────────────────────────────────────── */
  section[data-testid="stSidebar"] {
    background: #080e1c !important;
    border-right: 1px solid rgba(255,255,255,0.06) !important;
  }

  section[data-testid="stSidebar"] * {
    color: var(--white) !important;
  }

  /* ── Tool panels ──────────────────────────────────────────── */
  .tool-header {
    background: linear-gradient(135deg, rgba(37,99,235,0.12) 0%, rgba(37,99,235,0.04) 100%);
    border: 1px solid rgba(37,99,235,0.2);
    border-radius: 16px;
    padding: 1.5rem 1.75rem;
    margin-bottom: 1.5rem;
  }

  .tool-header h2 {
    font-size: 1.4rem;
    font-weight: 800;
    color: var(--white);
    margin: 0 0 0.3rem;
  }

  .tool-header p {
    font-size: 0.85rem;
    color: var(--muted);
    margin: 0;
  }

  /* ── Step progress ────────────────────────────────────────── */
  .step-row {
    display: flex;
    gap: 0;
    margin-bottom: 2rem;
    overflow-x: auto;
  }

  .step-item {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    position: relative;
    min-width: 80px;
  }

  .step-item:not(:last-child)::after {
    content: "";
    position: absolute;
    top: 16px;
    left: 50%;
    width: 100%;
    height: 2px;
    background: rgba(255,255,255,0.08);
  }

  .step-item.done:not(:last-child)::after {
    background: var(--blue);
  }

  .step-circle {
    width: 32px; height: 32px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.75rem;
    font-weight: 700;
    z-index: 1;
    background: rgba(255,255,255,0.06);
    border: 2px solid rgba(255,255,255,0.12);
    color: var(--muted);
    transition: all 0.3s ease;
  }

  .step-item.active .step-circle {
    background: var(--blue);
    border-color: var(--blue);
    color: white;
    box-shadow: 0 0 0 4px rgba(37,99,235,0.25);
  }

  .step-item.done .step-circle {
    background: rgba(37,99,235,0.3);
    border-color: var(--blue);
    color: #93c5fd;
  }

  .step-label {
    font-size: 0.65rem;
    color: var(--muted);
    margin-top: 6px;
    text-align: center;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .step-item.active .step-label {
    color: #93c5fd;
    font-weight: 600;
  }

  /* ── Result card ──────────────────────────────────────────── */
  .result-card {
    background: linear-gradient(145deg, rgba(22,44,109,0.4) 0%, rgba(10,16,29,0.7) 100%);
    border: 1px solid rgba(37,99,235,0.25);
    border-radius: 16px;
    padding: 1.5rem;
    margin-top: 1.5rem;
  }

  .result-metric {
    display: flex;
    flex-direction: column;
    align-items: center;
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 12px;
    padding: 1rem;
  }

  .result-metric .val {
    font-size: 2rem;
    font-weight: 800;
    color: var(--white);
  }

  .result-metric .lbl {
    font-size: 0.7rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  /* ── Quota warning ────────────────────────────────────────── */
  .quota-warning {
    background: rgba(220,38,38,0.1);
    border: 1px solid rgba(220,38,38,0.3);
    border-radius: 12px;
    padding: 1rem 1.25rem;
    color: #fca5a5;
    font-size: 0.88rem;
  }

  .quota-trial {
    background: rgba(234,179,8,0.08);
    border: 1px solid rgba(234,179,8,0.25);
    border-radius: 12px;
    padding: 1rem 1.25rem;
    color: #fcd34d;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }

  /* ── Admin table ────────────────────────────────────��─────── */
  .admin-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
  }

  .admin-table th {
    background: rgba(255,255,255,0.04);
    color: var(--muted);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    padding: 0.6rem 0.8rem;
    text-align: left;
    border-bottom: 1px solid rgba(255,255,255,0.06);
  }

  .admin-table td {
    padding: 0.65rem 0.8rem;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    color: var(--white);
    vertical-align: middle;
  }

  .admin-table tr:hover td {
    background: rgba(255,255,255,0.02);
  }

  /* ── Auth card ────────────────────────────────────────────── */
  .auth-card {
    background: linear-gradient(145deg, rgba(22,44,109,0.5) 0%, rgba(10,16,29,0.9) 100%);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 20px;
    padding: 2rem 2.5rem;
    max-width: 420px;
    margin: 2rem auto;
    backdrop-filter: blur(16px);
  }

  .auth-card h2 {
    font-size: 1.5rem;
    font-weight: 800;
    color: var(--white);
    margin-bottom: 0.4rem;
  }

  .auth-card p {
    font-size: 0.85rem;
    color: var(--muted);
    margin-bottom: 1.5rem;
  }

  /* ── Stacked input label override ────────────────────────── */
  .stTextInput label, .stPasswordInput label {
    color: var(--muted) !important;
    font-size: 0.8rem !important;
    font-weight: 500 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.07em !important;
  }

  .stTextInput input, .stPasswordInput input, .stTextArea textarea {
    background: rgba(255,255,255,0.05) !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 10px !important;
    color: var(--white) !important;
  }

  .stTextInput input:focus, .stPasswordInput input:focus {
    border-color: rgba(37,99,235,0.6) !important;
    box-shadow: 0 0 0 3px rgba(37,99,235,0.15) !important;
  }

  /* ── Button overrides ────────────────────────────────────── */
  .stButton > button {
    background: var(--blue) !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    font-weight: 600 !important;
    font-size: 0.9rem !important;
    padding: 0.55rem 1.5rem !important;
    transition: all 0.2s ease !important;
  }

  .stButton > button:hover {
    background: #1d4ed8 !important;
    transform: translateY(-1px);
    box-shadow: 0 4px 16px rgba(37,99,235,0.4) !important;
  }

  .stButton > button:active {
    transform: translateY(0) !important;
  }

  /* Danger button variant */
  .btn-danger > button {
    background: rgba(220,38,38,0.2) !important;
    border: 1px solid rgba(220,38,38,0.4) !important;
    color: #fca5a5 !important;
  }

  .stDownloadButton > button {
    background: linear-gradient(135deg, #16a34a 0%, #15803d 100%) !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    font-weight: 700 !important;
    font-size: 0.9rem !important;
    padding: 0.65rem 2rem !important;
    box-shadow: 0 4px 20px rgba(22,163,74,0.3) !important;
  }

  .stDownloadButton > button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 24px rgba(22,163,74,0.4) !important;
  }

  /* ── File uploader ───────────────────────────────────────── */
  [data-testid="stFileUploader"] {
    background: rgba(255,255,255,0.03) !important;
    border: 2px dashed rgba(37,99,235,0.3) !important;
    border-radius: 14px !important;
    padding: 1.5rem !important;
    transition: border-color 0.2s ease;
  }

  [data-testid="stFileUploader"]:hover {
    border-color: rgba(37,99,235,0.6) !important;
  }

  /* ── Selectbox ───────────────────────────────────────────── */
  .stSelectbox > div > div {
    background: rgba(255,255,255,0.05) !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 10px !important;
    color: var(--white) !important;
  }

  /* ── Spinner ────────────────────────────────────────────── */
  .stSpinner > div {
    border-top-color: var(--blue) !important;
  }

  /* ── Log status badges ───────────────────────────────────── */
  .log-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 0.68rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .log-success { background: rgba(22,163,74,0.2); color: #86efac; border: 1px solid rgba(22,163,74,0.3); }
  .log-error   { background: rgba(220,38,38,0.2); color: #fca5a5; border: 1px solid rgba(220,38,38,0.3); }
  .log-info    { background: rgba(37,99,235,0.2); color: #93c5fd; border: 1px solid rgba(37,99,235,0.3); }

  /* ── Animations ──────────────────────────────────────────── */
  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(20px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  /* ── Mobile responsive ───────────────────────────────────── */
  @media (max-width: 768px) {
    .ftth-navbar {
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .hero-stats {
      gap: 0.6rem;
    }
    .stat-badge {
      min-width: 90px;
      padding: 0.6rem 0.8rem;
    }
    .feature-grid {
      grid-template-columns: 1fr;
    }
    .auth-card {
      padding: 1.5rem 1.25rem;
    }
    .navbar-right {
      gap: 6px;
    }
    .nav-user-pill span:not(.avatar) {
      display: none;
    }
  }
</style>
"""

# ══════════════════════════════════════════════════════════════════════════════
# 7.  UI COMPONENTS
# ══════════════════════════════════════════════════════════════════════════════

def render_navbar():
    user = st.session_state.user
    role_badge = ""
    if user["role"] == "admin":
        role_badge = '<span class="nav-role-badge">Admin</span>'

    quota_color = "nav-quota-badge"
    quota_val = user["quota_remaining"]
    if quota_val == 0:
        quota_color = 'style="background:rgba(220,38,38,0.2);border:1px solid rgba(220,38,38,0.4);color:#fca5a5;border-radius:999px;padding:3px 10px;font-size:0.72rem;font-weight:600;"'
        quota_html = f'<span {quota_color}>Quota: 0</span>'
    else:
        quota_html = f'<span class="{quota_color}">Quota: {quota_val}</span>'

    initials = user["username"][:2].upper()

    st.markdown(f"""
    <div class="ftth-navbar">
      <div class="navbar-brand">
        <div class="logo-box">&#127760;</div>
        <span>FTTH Tools</span>
      </div>
      <div class="navbar-right">
        {role_badge}
        {quota_html}
        <div class="nav-user-pill">
          <div class="avatar">{initials}</div>
          <span>{user["username"]}</span>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)


def render_hero():
    st.markdown("""
    <div class="ftth-hero">
      <div class="hero-eyebrow">
        <div class="dot"></div>
        Platform FTTH Profesional
      </div>
      <h1 class="hero-title">
        Welcome to <span class="accent">FTTH Tools</span>
      </h1>
      <p class="hero-sub">
        Berhenti membuang waktu pada proses manual yang rumit. Sistem kami hadir untuk mengotomatisasi pekerjaan Anda, memberikan hasil instan yang akurat, dan menghemat waktu berharga Anda setiap hari.
      </p>
      <div class="hero-stats">
        <div class="stat-badge"><div class="val">10x</div><div class="lbl">Lebih Cepat</div></div>
        <div class="stat-badge"><div class="val">99%</div><div class="lbl">Akurasi</div></div>
        <div class="stat-badge"><div class="val">KML</div><div class="lbl">Input</div></div>
        <div class="stat-badge"><div class="val">BOQ</div><div class="lbl">Output</div></div>
      </div>
      <div class="feature-grid">
        <div class="feature-card">
          <div class="feature-icon">&#128196;</div>
          <div>
            <h4>KML to BOQ</h4>
            <p>Konversi file KML/KMZ ke Bill of Quantity Excel secara otomatis dan akurat.</p>
          </div>
        </div>
        <div class="feature-card">
          <div class="feature-icon">&#128202;</div>
          <div>
            <h4>KML to HPDB</h4>
            <p>Generate HPDB report langsung dari file KML Anda — segera hadir.</p>
          </div>
        </div>
        <div class="feature-card">
          <div class="feature-icon">&#9201;</div>
          <div>
            <h4>Proses Instan</h4>
            <p>Upload, proses, dan download — selesai dalam hitungan detik.</p>
          </div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)


def render_step_progress(current_step: int):
    """current_step: 1=upload, 2=processing, 3=done"""
    steps = ["Upload File", "Memproses", "Selesai"]
    html = '<div class="step-row">'
    for i, label in enumerate(steps, 1):
        css = ""
        symbol = str(i)
        if i < current_step:
            css = "done"
            symbol = "&#10003;"
        elif i == current_step:
            css = "active"
        html += f"""
        <div class="step-item {css}">
          <div class="step-circle">{symbol}</div>
          <div class="step-label">{label}</div>
        </div>"""
    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)


def render_quota_warning(quota: int):
    if quota == 0:
        st.markdown("""
        <div class="quota-warning">
          <strong>Quota Habis</strong> — Anda telah menggunakan semua quota trial Anda.
          Hubungi admin untuk menambah quota.
        </div>
        """, unsafe_allow_html=True)
        return False
    if quota <= 1:
        st.markdown(f"""
        <div class="quota-trial">
          &#9888; Sisa quota Anda: <strong>{quota}</strong>. Gunakan dengan bijak.
        </div>
        """, unsafe_allow_html=True)
    return True


# ══════════════════════════════════════════════════════════════════════════════
# 8.  AUTH PAGES
# ══════════════════════════════════════════════════════════════════════════════

def page_auth():
    st.markdown(HERO_CSS, unsafe_allow_html=True)

    # Minimal hero on auth page
    st.markdown("""
    <div style="text-align:center; padding: 2.5rem 1rem 1rem;">
      <div style="display:inline-flex;align-items:center;gap:10px;font-size:1.8rem;font-weight:900;color:#f8fafc;letter-spacing:-0.03em;margin-bottom:0.5rem;">
        <div style="width:40px;height:40px;background:#2563eb;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.2rem;">&#127760;</div>
        FTTH Tools
      </div>
      <p style="color:#94a3b8;font-size:0.9rem;">Platform Konversi KML Profesional</p>
    </div>
    """, unsafe_allow_html=True)

    # Tab selector
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        tab_choice = st.radio(
            "Mode",
            ["Login", "Daftar Akun"],
            horizontal=True,
            label_visibility="collapsed",
        )

        if tab_choice == "Login":
            _render_login_form()
        else:
            _render_register_form()


def _render_login_form():
    st.markdown('<div class="auth-card">', unsafe_allow_html=True)
    st.markdown('<h2>Masuk ke Akun</h2><p>Selamat datang kembali</p>', unsafe_allow_html=True)

    username = st.text_input("Username", key="login_user", placeholder="Masukkan username")
    password = st.text_input("Password", type="password", key="login_pass", placeholder="••••••••")

    if st.button("Login", use_container_width=True, key="btn_login"):
        if not username or not password:
            st.error("Username dan password wajib diisi.")
            return

        with st.spinner("Memverifikasi..."):
            user = get_user_by_username(username)

        if not user:
            st.error("Username atau password salah.")
            write_log(username=username, action="Login gagal — user tidak ditemukan", tool="auth", status="error")
            return

        if not user.get("is_active", True):
            st.error("Akun Anda dinonaktifkan. Hubungi admin.")
            return

        if not verify_password(password, user["password_hash"]):
            st.error("Username atau password salah.")
            write_log(username=username, action="Login gagal — password salah", tool="auth", status="error")
            return

        login_user(user)
        write_log(
            username=user["username"],
            action="Login berhasil",
            tool="auth",
            status="info",
            user_id=user["id"],
        )
        st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)

    # Admin hint
    st.markdown("""
    <div style="text-align:center;margin-top:1rem;font-size:0.75rem;color:#475569;">
      Default admin: <code style="background:rgba(255,255,255,0.06);padding:2px 6px;border-radius:4px;">admin</code>
      &nbsp;/&nbsp;
      <code style="background:rgba(255,255,255,0.06);padding:2px 6px;border-radius:4px;">admin123</code>
    </div>
    """, unsafe_allow_html=True)


def _render_register_form():
    st.markdown('<div class="auth-card">', unsafe_allow_html=True)
    st.markdown('<h2>Buat Akun Baru</h2><p>Gratis · 2 kali percobaan</p>', unsafe_allow_html=True)

    username = st.text_input("Username", key="reg_user", placeholder="min. 4 karakter")
    email = st.text_input("Email", key="reg_email", placeholder="nama@email.com")
    password = st.text_input("Password", type="password", key="reg_pass", placeholder="min. 6 karakter")
    password2 = st.text_input("Konfirmasi Password", type="password", key="reg_pass2", placeholder="Ulangi password")

    if st.button("Daftar Sekarang", use_container_width=True, key="btn_register"):
        if len(username) < 4:
            st.error("Username minimal 4 karakter.")
            return
        if password != password2:
            st.error("Password tidak cocok.")
            return

        with st.spinner("Mendaftarkan akun..."):
            ok, msg = register_user(username, email, password)

        if ok:
            st.success(msg)
            write_log(username=username, action="Registrasi akun baru", tool="auth", status="info")
        else:
            st.error(msg)

    st.markdown('</div>', unsafe_allow_html=True)


# ══════════════════════��═══════════════════════════════════════════════════════
# 9.  KML PROCESSING LOGIC  (bugs fixed + optimized)
# ══════════════════════════════════════════════════════════════════════════════

def _remove_ns_prefixes(xml_text: str) -> str:
    """Strip XML namespace prefixes so getElementsByTagName works reliably."""
    return re.sub(r"<(/?)([\w\-]+):", r"<\1", xml_text)


def _folder_name(folder) -> str:
    names = folder.getElementsByTagName("name")
    if names and names[0].firstChild:
        return names[0].firstChild.nodeValue.strip()
    return ""


def _parse_coords(text: str) -> list[tuple[float, float]]:
    coords = []
    for token in text.strip().split():
        parts = token.split(",")
        if len(parts) >= 2:
            try:
                lon, lat = float(parts[0]), float(parts[1])
                coords.append((lat, lon))
            except ValueError:
                continue
    return coords


def _calc_length_m(pm) -> float:
    """Return total polyline length in metres for a Placemark."""
    tags = pm.getElementsByTagName("coordinates")
    if not tags or not tags[0].firstChild:
        return 0.0
    pts = _parse_coords(tags[0].firstChild.nodeValue)
    def _haversine(p1, p2) -> float:
        """Pure-Python Haversine — no external library needed."""
        lat1, lon1 = math.radians(p1[0]), math.radians(p1[1])
        lat2, lon2 = math.radians(p2[0]), math.radians(p2[1])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        return 6_371_000 * 2 * math.asin(math.sqrt(a))

    return sum(_haversine(pts[i], pts[i + 1]) for i in range(len(pts) - 1))


def _find_folders(node) -> list:
    """Recursively find all Folder elements under node."""
    result = []
    if getattr(node, "tagName", None) == "Folder":
        result.append(node)
    for child in getattr(node, "childNodes", []):
        if getattr(child, "nodeType", None) == child.ELEMENT_NODE:
            result.extend(_find_folders(child))
    return result


def _safe_add(sheet, cell: str, value: float):
    sheet[cell] = (sheet[cell].value or 0) + round(value, 2)


def _is_true_fat(name: str) -> bool:
    upper = (name or "").upper()
    return "FAT" in upper and "COVER" not in upper


def _count_fat_in_folder(line_folder) -> int:
    total = 0
    for f in _find_folders(line_folder):
        if _is_true_fat(_folder_name(f)):
            total += len(f.getElementsByTagName("Placemark"))
    return total


def process_kml_to_boq(file_bytes: bytes, filename: str) -> tuple[bytes | None, str]:
    """
    Convert a KML/KMZ file to a filled BOQ Excel workbook.
    Returns (excel_bytes, message).  On failure, excel_bytes is None.
    """
    try:
        wb = openpyxl.load_workbook("BOQ_Template.xlsx")
    except FileNotFoundError:
        return None, "BOQ_Template.xlsx tidak ditemukan di root folder."

    sheet_ae = wb["BoM AE"]
    sheet_bo = wb["BoQ NRO Cluster"]

    # ── Parse input ────────────────────────────────────────────────────────
    try:
        if filename.lower().endswith(".kmz"):
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                kml_names = [n for n in zf.namelist() if n.lower().endswith(".kml")]
                if not kml_names:
                    return None, "KMZ tidak mengandung file KML."
                raw = zf.read(kml_names[0]).decode("utf-8", errors="replace")
        else:
            raw = file_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        return None, f"Gagal membaca file: {e}"

    # ── Parse XML once ─────────────────────────────────────────────────────
    try:
        cleaned = _remove_ns_prefixes(raw)
        doc = minidom.parseString(cleaned)
    except Exception as e:
        return None, f"XML tidak valid: {e}"

    all_folders = _find_folders(doc.documentElement)

    # ── FDT blocks (max 3, columns C / I / O) ─────────────────────────────
    FDT_COLS = ["C", "I", "O"]

    # Collect distribution & sling folders once (avoid re-iterating)
    dist_folders = [f for f in all_folders if "distribution" in _folder_name(f).lower()]
    sling_folders = [f for f in all_folders if "sling" in _folder_name(f).lower()]

    fdt_folders = [f for f in all_folders if "FDT" in _folder_name(f).upper()][:3]

    for idx, fdt_folder in enumerate(fdt_folders):
        col = FDT_COLS[idx]

        # ── Distribution cable lengths (scoped to placemarks under dist_folders)
        for dist_f in dist_folders:
            for pm in dist_f.getElementsByTagName("Placemark"):
                n_nodes = pm.getElementsByTagName("name")
                pm_name = (n_nodes[0].firstChild.nodeValue if n_nodes and n_nodes[0].firstChild else "").upper()
                length = _calc_length_m(pm)

                mapping = {
                    ("LINE A", "24C"): f"{col}2",  ("LINE A", "36C"): f"{col}6",  ("LINE A", "48C"): f"{col}10",
                    ("LINE B", "24C"): f"{col}3",  ("LINE B", "36C"): f"{col}7",  ("LINE B", "48C"): f"{col}11",
                    ("LINE C", "24C"): f"{col}4",  ("LINE C", "36C"): f"{col}8",  ("LINE C", "48C"): f"{col}12",
                    ("LINE D", "24C"): f"{col}5",  ("LINE D", "36C"): f"{col}9",  ("LINE D", "48C"): f"{col}13",
                }
                for (line, core), cell in mapping.items():
                    if line in pm_name and core in pm_name:
                        _safe_add(sheet_ae, cell, length)
                        break

        # ── FAT counts (scoped inside this FDT folder) ─────────────────────
        fat_line_map = {"LINE A": f"{col}36", "LINE B": f"{col}37", "LINE C": f"{col}38", "LINE D": f"{col}39"}
        for sub in fdt_folder.getElementsByTagName("Folder"):
            sub_name = _folder_name(sub).upper()
            if sub_name in fat_line_map:
                sheet_ae[fat_line_map[sub_name]] = _count_fat_in_folder(sub)

        # ── Sling cable total ──────────────────────────────────────────────
        total_sling = sum(_calc_length_m(pm) for sf in sling_folders for pm in sf.getElementsByTagName("Placemark"))
        sheet_ae[f"{col}15"] = round(total_sling, 2)

    # ── Pole counts ────────────────────────────────────────────────────────
    pole_map = {
        "new pole 7-4":        "C54",
        "new pole 7-2.5":      "C56",
        "new pole 7-3":        "C55",
        "new pole 9-4":        "C58",
        "existing pole emr 7-4": "C61",
    }
    pole_totals: dict[str, int] = {k: 0 for k in pole_map}
    for folder in all_folders:
        name_l = _folder_name(folder).lower()
        if name_l in pole_totals:
            pole_totals[name_l] += len(folder.getElementsByTagName("Placemark"))
    for k, cell in pole_map.items():
        sheet_ae[cell] = pole_totals[k]

    # ── HP Cover ────────────────────────────────────────────────────��─────���
    hp_cover = sum(
        len(f.getElementsByTagName("Placemark"))
        for f in all_folders
        if "hp cover" in _folder_name(f).lower()
    )
    sheet_bo["O5"] = hp_cover
    sheet_bo["O3"] = filename
    sheet_bo["O4"] = str(datetime.date.today())

    # ── Serialise ───────────────��──────────────────────────────────────────
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.getvalue(), f"HP Cover terdeteksi: {hp_cover}"


# ══════════════════════════════════════════════════════════════════════════════
# 10.  TOOL PAGES
# ══════════════════════════════════════════════════════════════════════════════

def page_kml_boq():
    user = st.session_state.user
    refresh_current_user()
    quota = st.session_state.user["quota_remaining"]

    st.markdown("""
    <div class="tool-header">
      <h2>&#128196; KML to BOQ Converter</h2>
      <p>Upload file KML atau KMZ dari survey FTTH Anda. Sistem akan mengisi template BOQ Excel secara otomatis.</p>
    </div>
    """, unsafe_allow_html=True)

    # Step 1 — quota check
    has_quota = render_quota_warning(quota)
    if not has_quota:
        return

    render_step_progress(1)

    uploaded = st.file_uploader(
        "Pilih file KML atau KMZ",
        type=["kml", "kmz"],
        help="Drag & drop atau klik untuk browse",
        key="boq_uploader",
    )

    if uploaded is None:
        st.markdown("""
        <div style="text-align:center;color:#475569;font-size:0.82rem;margin-top:0.5rem;">
          Format yang didukung: .kml .kmz &nbsp;·&nbsp; Maksimum 200 MB
        </div>
        """, unsafe_allow_html=True)
        return

    # File info pill
    size_kb = len(uploaded.getvalue()) / 1024
    st.markdown(f"""
    <div style="display:inline-flex;align-items:center;gap:8px;background:rgba(37,99,235,0.1);
      border:1px solid rgba(37,99,235,0.25);border-radius:8px;padding:6px 12px;font-size:0.8rem;
      color:#93c5fd;margin:0.5rem 0 1rem;">
      &#128196; <strong>{uploaded.name}</strong>&nbsp;·&nbsp;{size_kb:.1f} KB
    </div>
    """, unsafe_allow_html=True)

    render_step_progress(2)

    if st.button("Proses Sekarang", use_container_width=True, key="btn_process_boq"):
        # Deduct quota first
        if not deduct_quota(user["id"]):
            st.error("Quota tidak cukup.")
            return

        refresh_current_user()

        progress_bar = st.progress(0, text="Membaca file...")
        import time

        steps = [
            (20, "Parsing XML..."),
            (45, "Menghitung kabel distribusi..."),
            (65, "Menghitung FAT & Sling..."),
            (80, "Menghitung tiang..."),
            (90, "Mengisi template Excel..."),
            (100, "Selesai!"),
        ]

        result_bytes = None
        result_msg = ""

        with st.spinner(""):
            # Simulate staged progress while processing
            file_bytes = uploaded.getvalue()
            for pct, label in steps[:2]:
                progress_bar.progress(pct, text=label)
                time.sleep(0.15)

            result_bytes, result_msg = process_kml_to_boq(file_bytes, uploaded.name)

            for pct, label in steps[2:]:
                progress_bar.progress(pct, text=label)
                time.sleep(0.1)

        progress_bar.empty()

        if result_bytes is None:
            st.error(f"Proses gagal: {result_msg}")
            write_log(
                username=user["username"],
                action="KML to BOQ — gagal",
                tool="kml_boq",
                status="error",
                file_name=uploaded.name,
                details=result_msg,
                user_id=user["id"],
            )
            # Refund quota on error
            add_quota(user["id"], 1)
            refresh_current_user()
            return

        # Success
        render_step_progress(3)

        write_log(
            username=user["username"],
            action="KML to BOQ — berhasil",
            tool="kml_boq",
            status="success",
            file_name=uploaded.name,
            details=result_msg,
            user_id=user["id"],
        )

        refresh_current_user()
        new_quota = st.session_state.user["quota_remaining"]

        st.markdown(f"""
        <div class="result-card">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:1rem;">
            <div style="width:36px;height:36px;background:rgba(22,163,74,0.2);border-radius:10px;
              display:flex;align-items:center;justify-content:center;font-size:1.1rem;">&#9989;</div>
            <div>
              <div style="font-weight:700;color:#f8fafc;">Konversi Berhasil!</div>
              <div style="font-size:0.78rem;color:#94a3b8;">{result_msg}</div>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:0.75rem;">
            <div class="result-metric"><div class="val">{uploaded.name.split(".")[-1].upper()}</div><div class="lbl">Format Input</div></div>
            <div class="result-metric"><div class="val">XLSX</div><div class="lbl">Format Output</div></div>
            <div class="result-metric"><div class="val">{new_quota}</div><div class="lbl">Sisa Quota</div></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        output_name = f"BOQ_{uploaded.name.rsplit('.', 1)[0]}_{datetime.date.today()}.xlsx"
        st.download_button(
            label="Download BOQ Excel",
            data=result_bytes,
            file_name=output_name,
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
        )


def page_kml_hpdb():
    st.markdown("""
    <div class="tool-header">
      <h2>&#128202; KML to HPDB</h2>
      <p>Generate laporan HPDB dari file KML secara otomatis.</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="text-align:center;padding:4rem 2rem;">
      <div style="font-size:3rem;margin-bottom:1rem;">&#128679;</div>
      <h3 style="color:#f8fafc;font-size:1.2rem;font-weight:700;margin-bottom:0.5rem;">Segera Hadir</h3>
      <p style="color:#94a3b8;font-size:0.88rem;max-width:400px;margin:0 auto;">
        Fitur KML to HPDB sedang dalam pengembangan. Upload template HPDB Excel Anda
        dan fitur ini akan segera aktif.
      </p>
    </div>
    """, unsafe_allow_html=True)

    st.info("Untuk mengaktifkan fitur ini, upload file template HPDB Anda ke admin.")


# ══════════════════════════════════════════════════════════════════════════════
# 11.  ADMIN DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

def page_admin():
    st.markdown("""
    <div class="tool-header">
      <h2>&#9881; Admin Dashboard</h2>
      <p>Kelola pengguna, quota, dan pantau aktivitas sistem.</p>
    </div>
    """, unsafe_allow_html=True)

    tab_users, tab_logs, tab_add = st.tabs(["Kelola User", "Activity Log", "Tambah User"])

    # ── Tab 1: User management ──────────────��──────────────────────────────
    with tab_users:
        st.markdown("#### Daftar Pengguna")
        users = get_all_users()

        if not users:
            st.info("Belum ada pengguna terdaftar.")
        else:
            for u in users:
                with st.container():
                    c1, c2, c3, c4, c5, c6 = st.columns([2, 2, 1, 1, 1, 2])
                    with c1:
                        role_color = "#fcd34d" if u["role"] == "admin" else "#93c5fd"
                        st.markdown(f"**{u['username']}**<br><span style='font-size:0.72rem;color:{role_color};'>{u['role'].upper()}</span>", unsafe_allow_html=True)
                    with c2:
                        st.markdown(f"<span style='font-size:0.8rem;color:#94a3b8;'>{u.get('email','')}</span>", unsafe_allow_html=True)
                    with c3:
                        status_col = "#86efac" if u.get("is_active", True) else "#fca5a5"
                        status_lbl = "Aktif" if u.get("is_active", True) else "Nonaktif"
                        st.markdown(f"<span style='color:{status_col};font-size:0.8rem;'>{status_lbl}</span>", unsafe_allow_html=True)
                    with c4:
                        st.markdown(f"<span style='font-size:0.85rem;color:#f8fafc;font-weight:700;'>{u['quota_remaining']}</span><span style='color:#94a3b8;font-size:0.72rem;'> / {u['quota_total']}</span>", unsafe_allow_html=True)
                    with c5:
                        add_key = f"add_q_{u['id']}"
                        if st.button("+5", key=add_key, help="Tambah 5 quota"):
                            if add_quota(u["id"], 5):
                                write_log(
                                    username=st.session_state.user["username"],
                                    action=f"Admin tambah quota +5 untuk {u['username']}",
                                    tool="admin",
                                    status="info",
                                    user_id=st.session_state.user["id"],
                                )
                                st.rerun()
                    with c6:
                        act_key = f"toggle_{u['id']}"
                        del_key = f"del_{u['id']}"
                        col_a, col_b = st.columns(2)
                        with col_a:
                            toggle_lbl = "Nonaktifkan" if u.get("is_active", True) else "Aktifkan"
                            if st.button(toggle_lbl, key=act_key):
                                new_status = not u.get("is_active", True)
                                set_user_active(u["id"], new_status)
                                write_log(
                                    username=st.session_state.user["username"],
                                    action=f"Admin {'nonaktifkan' if not new_status else 'aktifkan'} user {u['username']}",
                                    tool="admin",
                                    status="info",
                                    user_id=st.session_state.user["id"],
                                )
                                st.rerun()
                        with col_b:
                            if u["username"] != "admin":
                                if st.button("Hapus", key=del_key):
                                    delete_user(u["id"])
                                    write_log(
                                        username=st.session_state.user["username"],
                                        action=f"Admin hapus user {u['username']}",
                                        tool="admin",
                                        status="info",
                                        user_id=st.session_state.user["id"],
                                    )
                                    st.rerun()

                    st.markdown("<hr style='border-color:rgba(255,255,255,0.05);margin:0.5rem 0;'>", unsafe_allow_html=True)

    # ── Tab 2: Activity logs ───────────────────────────────────────────────
    with tab_logs:
        st.markdown("#### Log Aktivitas Terbaru")

        col_ref, col_filter = st.columns([1, 3])
        with col_ref:
            if st.button("Refresh Log", key="refresh_logs"):
                st.rerun()
        with col_filter:
            filter_tool = st.selectbox(
                "Filter Tool",
                ["Semua", "kml_boq", "auth", "admin"],
                key="log_filter",
                label_visibility="collapsed",
            )

        logs = get_recent_logs(200)
        if filter_tool != "Semua":
            logs = [l for l in logs if l.get("tool") == filter_tool]

        if not logs:
            st.info("Belum ada log aktivitas.")
        else:
            # Stats row
            success_c = sum(1 for l in logs if l["status"] == "success")
            error_c = sum(1 for l in logs if l["status"] == "error")
            col_s, col_e, col_t = st.columns(3)
            col_s.metric("Sukses", success_c)
            col_e.metric("Error", error_c)
            col_t.metric("Total", len(logs))

            st.markdown("<div style='margin-top:1rem;'>", unsafe_allow_html=True)
            for log in logs[:50]:
                ts = log.get("created_at", "")[:19].replace("T", " ")
                status = log.get("status", "info")
                badge_cls = f"log-{status}"
                fname = f" &nbsp;·&nbsp; <span style='color:#64748b;'>{log.get('file_name','')}</span>" if log.get("file_name") else ""
                st.markdown(f"""
                <div style="display:flex;align-items:center;gap:10px;padding:0.6rem 0;border-bottom:1px solid rgba(255,255,255,0.04);">
                  <span class="log-badge {badge_cls}">{status}</span>
                  <span style="color:#94a3b8;font-size:0.72rem;min-width:130px;">{ts}</span>
                  <span style="color:#60a5fa;font-size:0.78rem;min-width:80px;">{log.get('username','')}</span>
                  <span style="color:#f8fafc;font-size:0.8rem;flex:1;">{log.get('action','')}{fname}</span>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

    # ── Tab 3: Add user ────────────────────────────────────────────────────
    with tab_add:
        st.markdown("#### Tambah Pengguna Baru")
        with st.form("admin_add_user_form"):
            new_u = st.text_input("Username", placeholder="min. 4 karakter")
            new_e = st.text_input("Email", placeholder="nama@email.com")
            new_p = st.text_input("Password", type="password", placeholder="min. 6 karakter")
            new_role = st.selectbox("Role", ["user", "admin"])
            new_quota = st.number_input("Quota Awal", min_value=1, max_value=9999, value=10)

            submitted = st.form_submit_button("Tambah User", use_container_width=True)

        if submitted:
            if len(new_u) < 4:
                st.error("Username minimal 4 karakter.")
            elif len(new_p) < 6:
                st.error("Password minimal 6 karakter.")
            else:
                ok, msg = register_user(new_u, new_e, new_p)
                if ok:
                    # Update role & quota if different from default
                    user_rec = get_user_by_username(new_u)
                    if user_rec:
                        supabase().table("users").update({
                            "role": new_role,
                            "quota_remaining": new_quota,
                            "quota_total": new_quota,
                        }).eq("id", user_rec["id"]).execute()
                    st.success(f"User '{new_u}' berhasil ditambahkan.")
                    write_log(
                        username=st.session_state.user["username"],
                        action=f"Admin buat user baru: {new_u} ({new_role})",
                        tool="admin",
                        status="info",
                        user_id=st.session_state.user["id"],
                    )
                else:
                    st.error(msg)


# ══════════════════════════════════════════════════════════════════════════════
# 12.  MAIN ROUTER
# ══════════════════════════════════════════════════════════════════════════════

def main():
    init_session()

    # Inject global CSS
    st.markdown(HERO_CSS, unsafe_allow_html=True)

    # ── Not authenticated → show auth page ────────────────────────────────
    if not st.session_state.authenticated:
        page_auth()
        return

    user = st.session_state.user

    # ── Navbar ─────────────────────────────────────────────────────────────
    render_navbar()

    # ── Sidebar ────────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("""
        <div style="padding:1rem 0.5rem 0.5rem;">
          <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:#475569;margin-bottom:0.75rem;">
            Tools
          </div>
        </div>
        """, unsafe_allow_html=True)

        menu_items = ["Beranda", "KML to BOQ", "KML to HPDB"]
        if user["role"] == "admin":
            menu_items.append("Admin Dashboard")

        selected = st.radio(
            "Navigasi",
            menu_items,
            label_visibility="collapsed",
            key="sidebar_nav",
        )

        st.markdown("<hr style='border-color:rgba(255,255,255,0.08);margin:1rem 0;'>", unsafe_allow_html=True)

        # User info card in sidebar
        quota = user["quota_remaining"]
        quota_pct = int((quota / max(user["quota_total"], 1)) * 100)
        bar_color = "#2563eb" if quota_pct > 30 else "#dc2626"

        st.markdown(f"""
        <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.07);
          border-radius:12px;padding:1rem;margin-bottom:1rem;">
          <div style="font-size:0.72rem;color:#94a3b8;margin-bottom:0.25rem;">Quota</div>
          <div style="font-size:1.4rem;font-weight:800;color:#f8fafc;line-height:1;">{quota}</div>
          <div style="font-size:0.7rem;color:#64748b;">dari {user['quota_total']} total</div>
          <div style="background:rgba(255,255,255,0.08);border-radius:999px;height:4px;margin-top:0.5rem;">
            <div style="background:{bar_color};height:4px;border-radius:999px;width:{quota_pct}%;transition:width 0.3s;"></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Logout", use_container_width=True, key="sidebar_logout"):
            logout_user()
            st.rerun()

    # ── Route ──────────────────────────────────────────────────────────────
    if selected == "Beranda":
        render_hero()
    elif selected == "KML to BOQ":
        page_kml_boq()
    elif selected == "KML to HPDB":
        page_kml_hpdb()
    elif selected == "Admin Dashboard" and user["role"] == "admin":
        page_admin()


if __name__ == "__main__":
    main()
