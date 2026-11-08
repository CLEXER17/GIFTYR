# Telegram bot version of LVGyFTR.py (original script by LootVerse @lootverseoffers)
# Flow: send number -> bot sends OTP -> send OTP -> send points -> result.
#
# Env vars:
#   BOT_TOKEN     Telegram bot token from @BotFather            (required)
#   ADMIN_ID      your Telegram user ID, comma-separated for more (required)
#   SESSION_FILE  default /data/numbersession.json (mount a Railway Volume at /data)
#   USERS_FILE    default: users.json next to SESSION_FILE (user registry + bans)
#   BUTTON_COLORS 1 (default) = coloured buttons, 0 = plain
#   NOTIFY_NEW_USERS 1 (default) = DM admins when a new user starts the bot
#   OTP_COOLDOWN  seconds between OTP requests per user (default 45, admins exempt)
#   OTP_DAILY_LIMIT  max OTP requests per user per 24h (default 10, admins exempt)

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import requests
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, LinkPreviewOptions, Update
from telegram.error import BadRequest
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO
)
log = logging.getLogger("gyftr-bot")
logging.getLogger("httpx").setLevel(logging.WARNING)

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS = {
    int(x) for x in os.getenv("ADMIN_ID", "").replace(" ", "").split(",") if x.isdigit()
}
SESSION_FILE = os.getenv("SESSION_FILE", "/data/numbersession.json")
# Coloured (blue/green/red) buttons via Telegram button styles. Set to 0 to disable.
BUTTON_COLORS = os.getenv("BUTTON_COLORS", "1") != "0"
USERS_FILE = os.getenv("USERS_FILE", "")
NOTIFY_NEW_USERS = os.getenv("NOTIFY_NEW_USERS", "1") != "0"
OTP_COOLDOWN = int(os.getenv("OTP_COOLDOWN", "45"))
OTP_DAILY_LIMIT = int(os.getenv("OTP_DAILY_LIMIT", "10"))

API_BASE = "https://api.gyftr.com"
CAMPAIGN = "DIWALI2026"
CAMPAIGN_PATH = "diwali2026"
PASSPHRASE = "d909dg78609e47ak47diy4cf87t90c4a"
PLAY_PATH = f"/gyftrapi/api/v1/caimpaign/{CAMPAIGN_PATH}"

MIN_POINTS = 1
MAX_POINTS = 150

HEADERS = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": "https://www.gyftr.com",
    "referer": "https://www.gyftr.com/",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
    ),
}

AUTH_HEADERS = {
    "device": "desktop",
    "platform": "web",
    "cache-control": "no-cache, no-store, must-revalidate",
    "pragma": "no-cache",
}

_file_lock = threading.RLock()


# --------------------------------------------------------------------------- #
# Crypto (CryptoJS-compatible AES)
# --------------------------------------------------------------------------- #
def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16):
    out, prev = b"", b""
    while len(out) < key_len + iv_len:
        prev = hashlib.md5(prev + password + salt).digest()
        out += prev
    return out[:key_len], out[key_len:key_len + iv_len]


def encrypt_cryptojs(plaintext: bytes, passphrase: str = PASSPHRASE) -> str:
    salt = os.urandom(8)
    key, iv = _evp_bytes_to_key(passphrase.encode(), salt)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(b"Salted__" + salt + ct).decode()


def decrypt_cryptojs(b64_blob: str, passphrase: str = PASSPHRASE) -> bytes:
    raw = base64.b64decode(b64_blob)
    if raw[:8] != b"Salted__":
        raise ValueError("not a CryptoJS Salted__ blob")
    salt, ct = raw[8:16], raw[16:]
    key, iv = _evp_bytes_to_key(passphrase.encode(), salt)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def jwt_seconds_left(token: str) -> int:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0)
        return int(exp - time.time())
    except Exception:
        return 0


# --------------------------------------------------------------------------- #
# Session storage
# --------------------------------------------------------------------------- #
def _ensure_session_dir() -> None:
    global SESSION_FILE, USERS_FILE
    folder = os.path.dirname(SESSION_FILE) or "."
    try:
        os.makedirs(folder, exist_ok=True)
        test = os.path.join(folder, ".w")
        with open(test, "w") as fh:
            fh.write("x")
        os.remove(test)
    except Exception as exc:
        log.warning("Cannot write to %s (%s); using ./numbersession.json "
                    "(will NOT survive redeploys — mount a Volume)", folder, exc)
        SESSION_FILE = "numbersession.json"
    if not USERS_FILE:
        USERS_FILE = os.path.join(os.path.dirname(SESSION_FILE) or ".", "users.json")


def _read_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_json(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    os.replace(tmp, path)


# ---- per-user Gyftr sessions: {"<telegram_id>": {"<mobile>": {...}}} ------- #
def _load_all_sessions() -> dict:
    data = _read_json(SESSION_FILE)
    # legacy flat format {mobile: {token: ...}} -> assign to first admin
    if data and any(isinstance(v, dict) and "token" in v for v in data.values()):
        owner = str(sorted(ADMIN_IDS)[0]) if ADMIN_IDS else "0"
        data = {owner: data}
        _write_json(SESSION_FILE, data)
        log.info("Migrated legacy sessions to admin %s", owner)
    return data


def load_sessions(uid: int) -> dict:
    with _file_lock:
        return dict(_load_all_sessions().get(str(uid), {}))


def save_sessions(uid: int, sessions: dict) -> None:
    with _file_lock:
        data = _load_all_sessions()
        data[str(uid)] = sessions
        _write_json(SESSION_FILE, data)


def update_token(uid: int, mobile: str, new_token: str) -> None:
    with _file_lock:
        data = _load_all_sessions()
        entry = data.get(str(uid), {}).get(mobile)
        if entry:
            entry["token"] = new_token
            entry["expires_in_s"] = jwt_seconds_left(new_token)
            _write_json(SESSION_FILE, data)


def total_saved_numbers() -> int:
    with _file_lock:
        return sum(len(v) for v in _load_all_sessions().values() if isinstance(v, dict))


# ---- user registry: {"<telegram_id>": {...}} -------------------------------- #
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_users() -> dict:
    with _file_lock:
        return _read_json(USERS_FILE)


def upsert_user(user) -> tuple[bool, dict]:
    with _file_lock:
        users = _read_json(USERS_FILE)
        key = str(user.id)
        rec = users.get(key)
        is_new = rec is None
        if is_new:
            rec = {"id": user.id, "banned": False, "first_seen": _now(), "plays": 0}
        rec.update(
            first_name=user.first_name or "",
            last_name=user.last_name or "",
            username=user.username or "",
            last_seen=_now(),
        )
        users[key] = rec
        _write_json(USERS_FILE, users)
        return is_new, dict(rec)


def get_user(uid: int) -> Optional[dict]:
    return load_users().get(str(uid))


def set_banned(uid: int, flag: bool) -> Optional[dict]:
    with _file_lock:
        users = _read_json(USERS_FILE)
        rec = users.get(str(uid))
        if not rec:
            return None
        rec["banned"] = flag
        rec["banned_at" if flag else "unbanned_at"] = _now()
        _write_json(USERS_FILE, users)
        return dict(rec)


def add_play(uid: int) -> None:
    with _file_lock:
        users = _read_json(USERS_FILE)
        rec = users.get(str(uid))
        if rec:
            rec["plays"] = int(rec.get("plays", 0)) + 1
            _write_json(USERS_FILE, users)


def find_user(query: str) -> Optional[dict]:
    q = query.strip().lstrip("@").lower()
    if not q:
        return None
    users = load_users()
    if q.isdigit() and q in users:
        return users[q]
    for rec in users.values():
        if (rec.get("username") or "").lower() == q:
            return rec
    return None


# --------------------------------------------------------------------------- #
# Gyftr API (blocking — always called through asyncio.to_thread)
# --------------------------------------------------------------------------- #
def api_call(session: requests.Session, method: str, path: str,
             *, params=None, body=None, token=None, auth=False) -> dict:
    headers = {}
    if auth:
        headers.update(AUTH_HEADERS)
        if token:
            headers["token"] = token

    r = session.request(method, API_BASE + path, params=params, data=body,
                        headers=headers, timeout=30)
    try:
        payload = r.json()
    except ValueError:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
    if payload.get("code") not in (200, 201, 202) or payload.get("status") not in ("SUCCESS", None):
        err = RuntimeError(payload.get("message") or f"HTTP {r.status_code}")
        err.payload = payload  # type: ignore[attr-defined]
        raise err
    return payload


def _enc_body(obj: dict) -> str:
    enc = encrypt_cryptojs(json.dumps(obj, separators=(",", ":")).encode())
    return json.dumps({"encryptedBody": enc}, separators=(",", ":"))


def api_send_otp(mobile: str) -> tuple[requests.Session, str]:
    sess = requests.Session()
    sess.headers.update(HEADERS)
    resp = api_call(
        sess, "POST", "/gyftrapi/api/v1/chrismas/checkMobile",
        params={"campaign": CAMPAIGN}, body=_enc_body({"mobile": mobile}),
    )
    return sess, str(resp.get("message") or "OTP sent")


def api_verify_otp(sess: requests.Session, mobile: str, otp: str) -> dict:
    resp = api_call(
        sess, "POST", "/gyftrapi/api/v1/chrismas/validateOtp",
        params={"campaign": CAMPAIGN}, body=_enc_body({"mobile": mobile, "otp": otp}),
    )
    token = resp.get("token")
    if not token:
        raise RuntimeError("Server did not return a token")

    try:
        pr = api_call(
            sess, "GET", "/gyftrapi/api/v1/user/profile",
            params={"_": str(int(time.time() * 1000))}, token=token, auth=True,
        )
        if pr.get("token"):
            token = pr["token"]
    except Exception as exc:
        log.warning("Profile call after login failed (%s); keeping validateOtp token", exc)

    return {
        "mobile": mobile,
        "token": token,
        "campaign": CAMPAIGN,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "expires_in_s": jwt_seconds_left(token),
    }


def api_fetch_profile(token: str) -> dict:
    sess = requests.Session()
    sess.headers.update(HEADERS)
    resp = api_call(
        sess, "GET", "/gyftrapi/api/v1/user/profile",
        params={"_": str(int(time.time() * 1000))}, token=token, auth=True,
    )
    decrypted = None
    if resp.get("data") and isinstance(resp["data"], str):
        try:
            raw = decrypt_cryptojs(resp["data"]).decode()
            try:
                decrypted = json.loads(raw)
            except json.JSONDecodeError:
                decrypted = raw
        except Exception:
            pass
    return {"decrypted": decrypted, "rotated_token": resp.get("token")}


def api_play(token: str, user_type: str, points: int) -> dict:
    sess = requests.Session()
    sess.headers.update(HEADERS)
    resp = api_call(
        sess, "POST", PLAY_PATH,
        body=_enc_body({"user_type": user_type, "points": points}),
        token=token, auth=True,
    )
    return resp


# --------------------------------------------------------------------------- #
# Telegram UI helpers
# --------------------------------------------------------------------------- #
MAX_LEN = {"mobile": 10, "otp": 8, "points": 3}
PRESETS = (10, 50, 100, 150)
PAGE_SIZE = 8
NO_PREVIEW = LinkPreviewOptions(is_disabled=True)

_otp_log: dict[int, list[float]] = {}


def btn(text: str, data: str, style: Optional[str] = None) -> InlineKeyboardButton:
    """style: 'primary' (blue) | 'success' (green) | 'danger' (red)."""
    if style and BUTTON_COLORS:
        return InlineKeyboardButton(text, callback_data=data, api_kwargs={"style": style})
    return InlineKeyboardButton(text, callback_data=data)


def uid_of(update: Update) -> int:
    return update.effective_user.id


def is_admin_id(uid: int) -> bool:
    return uid in ADMIN_IDS


def norm_mobile(text: str) -> Optional[str]:
    digits = re.sub(r"\D", "", text)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    if len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    return digits if re.fullmatch(r"[6-9]\d{9}", digits) else None


def clear_state(ud: dict) -> None:
    for k in ("state", "sess", "mobile", "user_type", "buf", "hdr"):
        ud.pop(k, None)


def short_err(exc: Exception) -> str:
    raw = getattr(exc, "payload", None)
    if raw:
        return f"{exc}\n{json.dumps(raw)[:500]}"
    return str(exc)


def otp_check(uid: int) -> Optional[str]:
    """Anti-abuse: returns an error message if this user must wait, else None."""
    if is_admin_id(uid):
        return None
    now = time.time()
    hist = [t for t in _otp_log.get(uid, []) if now - t < 86400]
    _otp_log[uid] = hist
    if hist and now - hist[-1] < OTP_COOLDOWN:
        return f"⏳ Wait {int(OTP_COOLDOWN - (now - hist[-1]))}s before requesting another OTP."
    if len(hist) >= OTP_DAILY_LIMIT:
        return "⚠️ Daily OTP limit reached. Try again tomorrow."
    return None


def otp_mark(uid: int) -> None:
    _otp_log.setdefault(uid, []).append(time.time())


async def say(update: Update, text: str, markup: Optional[InlineKeyboardMarkup] = None,
              html_mode: bool = False) -> None:
    """Edit the panel message on button taps, send a new message on typed input."""
    kwargs = {"reply_markup": markup, "link_preview_options": NO_PREVIEW}
    if html_mode:
        kwargs["parse_mode"] = "HTML"
    q = update.callback_query
    if q and q.message:
        try:
            await q.edit_message_text(text, **kwargs)
        except BadRequest as exc:
            if "not modified" not in str(exc).lower():
                raise
    else:
        await update.effective_chat.send_message(text, **kwargs)


def keypad_rows() -> list:
    return [
        [btn("1", "k:1"), btn("2", "k:2"), btn("3", "k:3")],
        [btn("4", "k:4"), btn("5", "k:5"), btn("6", "k:6")],
        [btn("7", "k:7"), btn("8", "k:8"), btn("9", "k:9")],
        [btn("⌫", "k:del", "danger"), btn("0", "k:0"), btn("🧹 Clear", "k:clr", "danger")],
        [btn("⬅️ Back", "b:back", "danger"), btn("✅ Submit", "k:ok", "success")],
    ]


def points_rows() -> list:
    return [[btn(f"⚡ {p}", f"p:{p}", "primary") for p in PRESETS]] + keypad_rows()


def menu_markup(uid: int) -> InlineKeyboardMarkup:
    rows = [
        [btn("📱 New Number", "m:new", "success")],
        [btn("📂 Saved Sessions", "m:sess", "primary")],
        [btn("❓ Help", "m:help", "primary")],
    ]
    if is_admin_id(uid):
        rows.append([btn("🛠 Admin Panel", "a:menu", "danger")])
    return InlineKeyboardMarkup(rows)


def after_play_markup() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [btn("📱 New Number", "m:new", "success"), btn("📂 Sessions", "m:sess", "primary")],
        [btn("🏠 Menu", "m:menu", "primary")],
    ])


# --------------------------------------------------------------------------- #
# User display helpers (admin side)
# --------------------------------------------------------------------------- #
def full_name(rec: dict) -> str:
    return f"{rec.get('first_name', '')} {rec.get('last_name', '')}".strip()


def user_html(rec: dict) -> str:
    """Username if present, otherwise a direct tg://user?id= profile link."""
    name = html.escape(full_name(rec) or "No name")
    un = rec.get("username")
    if un:
        return f'<a href="https://t.me/{un}">{name}</a> (@{un})'
    return f'<a href="tg://user?id={rec["id"]}">{name}</a> (no username, profile link)'


def user_label(rec: dict) -> str:
    icon = "🚫" if rec.get("banned") else "🟢"
    who = f"@{rec['username']}" if rec.get("username") else (full_name(rec) or str(rec["id"]))
    return f"{icon} {who}"[:40]


def short_dt(iso: Optional[str]) -> str:
    return iso[:16].replace("T", " ") + " UTC" if iso else "—"


# --------------------------------------------------------------------------- #
# Gate: register user, enforce bans
# --------------------------------------------------------------------------- #
async def gate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    if not user or user.is_bot:
        return False
    is_new, rec = upsert_user(user)

    if is_new and NOTIFY_NEW_USERS and not is_admin_id(user.id):
        for aid in ADMIN_IDS:
            try:
                await context.bot.send_message(
                    aid, f"🆕 New user\n{user_html(rec)}\n🆔 <code>{user.id}</code>",
                    parse_mode="HTML", link_preview_options=NO_PREVIEW,
                )
            except Exception:
                pass

    if is_admin_id(user.id):
        return True
    if rec.get("banned"):
        q = update.callback_query
        if q:
            await q.answer("🚫 You are banned from this bot.", show_alert=True)
        elif update.effective_message:
            await update.effective_message.reply_text("🚫 You are banned from using this bot.")
        return False
    return True


# --------------------------------------------------------------------------- #
# User screens
# --------------------------------------------------------------------------- #
async def screen_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    clear_state(context.user_data)
    uid = uid_of(update)
    n = len(load_sessions(uid))
    await say(
        update,
        f"🪔 Gyftr {CAMPAIGN} bot\n\nYour saved numbers: {n}\nChoose an option:",
        menu_markup(uid),
    )


async def screen_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await say(
        update,
        "How to use:\n"
        "1. 📱 New Number -> enter number -> OTP -> points\n"
        "2. 📂 Saved Sessions -> tap a number -> points\n\n"
        "You can use the keypad or just type the digits.\n"
        "Your saved numbers are private to your Telegram account.\n"
        "/start menu   /sessions saved numbers   /cancel reset",
        InlineKeyboardMarkup([[btn("⬅️ Back", "m:menu", "danger")]]),
    )


async def screen_sessions(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    clear_state(context.user_data)
    sessions = load_sessions(uid_of(update))
    rows = []
    for mobile, s in sessions.items():
        left = jwt_seconds_left(s.get("token", ""))
        if left > 0:
            rows.append([btn(f"🟢 {mobile}  (~{left // 86400}d left)", f"s:{mobile}", "primary")])
        else:
            rows.append([btn(f"🔴 {mobile}  (expired)", f"s:{mobile}", "danger")])
    rows.append([btn("📱 New Number", "m:new", "success")])
    rows.append([btn("⬅️ Back", "m:menu", "danger")])
    text = "📂 Saved sessions:" if sessions else "📂 No saved sessions yet."
    await say(update, text, InlineKeyboardMarkup(rows))


async def screen_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Render the keypad screen for the current state (mobile / otp / points)."""
    ud = context.user_data
    state, buf = ud.get("state"), ud.get("buf", "")

    if state == "mobile":
        text = (f"📱 Enter mobile number\n\n"
                f"➡️  {buf or '—'}   ({len(buf)}/10)\n\n"
                f"Use the keypad or type it.")
        rows = keypad_rows()
    elif state == "otp":
        text = (f"🔐 OTP sent to {ud.get('mobile')}\n\n"
                f"➡️  {buf or '—'}\n\n"
                f"Enter the OTP with the keypad or type it.")
        rows = keypad_rows()
    elif state == "points":
        text = (f"{ud.get('hdr', '')}\n\n"
                f"🎯 Points: {buf or '—'}   ({MIN_POINTS}-{MAX_POINTS})\n\n"
                f"Pick a preset, use the keypad, or type it.")
        rows = points_rows()
    else:
        await screen_menu(update, context)
        return
    await say(update, text, InlineKeyboardMarkup(rows))


# --------------------------------------------------------------------------- #
# User actions
# --------------------------------------------------------------------------- #
async def submit_mobile(update: Update, context: ContextTypes.DEFAULT_TYPE, mobile: str) -> None:
    ud = context.user_data
    uid = uid_of(update)

    wait = otp_check(uid)
    if wait:
        ud.update(state="mobile", buf=mobile)
        await say(update, f"{wait}\n\n➡️  {mobile}", InlineKeyboardMarkup(keypad_rows()))
        return
    otp_mark(uid)

    await say(update, f"⏳ Sending OTP to {mobile} ...")
    try:
        sess, msg = await asyncio.to_thread(api_send_otp, mobile)
    except Exception as exc:
        ud.update(state="mobile", buf=mobile)
        await say(
            update,
            f"❌ Could not send OTP:\n{short_err(exc)}\n\n➡️  {mobile}",
            InlineKeyboardMarkup(keypad_rows()),
        )
        return
    ud.update(state="otp", sess=sess, mobile=mobile, buf="")
    await update.effective_chat.send_message(f"✅ {msg}")
    await screen_input(update, context)


async def submit_otp(update: Update, context: ContextTypes.DEFAULT_TYPE, otp: str) -> None:
    ud = context.user_data
    uid = uid_of(update)
    mobile, sess = ud["mobile"], ud["sess"]
    await say(update, "⏳ Verifying OTP ...")
    try:
        entry = await asyncio.to_thread(api_verify_otp, sess, mobile, otp)
    except Exception as exc:
        ud["buf"] = ""
        await say(
            update,
            f"❌ OTP verification failed:\n{short_err(exc)}\n\n🔐 Enter OTP again for {mobile}",
            InlineKeyboardMarkup(keypad_rows()),
        )
        return
    sessions = load_sessions(uid)
    sessions[mobile] = entry
    save_sessions(uid, sessions)
    await prepare_play(update, context, mobile)


async def prepare_play(update: Update, context: ContextTypes.DEFAULT_TYPE, mobile: str) -> None:
    """Check profile for a logged-in number, then show the points screen."""
    ud = context.user_data
    uid = uid_of(update)
    entry = load_sessions(uid).get(mobile)
    back = InlineKeyboardMarkup([[btn("⬅️ Back", "m:menu", "danger")]])

    if not entry or not entry.get("token"):
        await say(update, "No token stored for this number. Log in again.", menu_markup(uid))
        return
    if jwt_seconds_left(entry["token"]) <= 0:
        await say(
            update,
            f"⚠️ Session for {mobile} expired. Log in again.",
            InlineKeyboardMarkup([
                [btn("📱 New Number", "m:new", "success")],
                [btn("⬅️ Back", "m:sess", "danger")],
            ]),
        )
        return

    await say(update, f"⏳ Checking session for {mobile} ...")
    try:
        profile = await asyncio.to_thread(api_fetch_profile, entry["token"])
    except Exception as exc:
        await say(update, f"❌ Profile check failed:\n{short_err(exc)}", back)
        return

    if profile.get("rotated_token"):
        await asyncio.to_thread(update_token, uid, mobile, profile["rotated_token"])

    pdata = profile.get("decrypted")
    user_type, already_played, balance = "B2C", False, None
    if isinstance(pdata, dict):
        user_type = str(pdata.get("user_type") or "B2C")
        already_played = bool(pdata.get("alreadyPlayed"))
        balance = pdata.get("epay_balance")

    hdr = f"✅ Logged in: {mobile}\n👤 Type: {user_type}"
    if balance is not None:
        hdr += f"\n💰 E-pay balance: ₹{balance}"

    if already_played:
        clear_state(ud)
        await say(update, f"{hdr}\n\n⚠️ Already played {CAMPAIGN} today.", after_play_markup())
        return

    ud.update(state="points", mobile=mobile, user_type=user_type, buf="", hdr=hdr)
    ud.pop("sess", None)
    await screen_input(update, context)


async def submit_points(update: Update, context: ContextTypes.DEFAULT_TYPE, pts: int) -> None:
    ud = context.user_data
    uid = uid_of(update)
    mobile, user_type = ud["mobile"], ud["user_type"]
    entry = load_sessions(uid).get(mobile)
    if not entry or jwt_seconds_left(entry.get("token", "")) <= 0:
        clear_state(ud)
        await say(update, "⚠️ Session expired. Log in again.", menu_markup(uid))
        return

    await say(update, f"🎲 Playing {CAMPAIGN}  type={user_type}  points={pts} ...")
    try:
        resp = await asyncio.to_thread(api_play, entry["token"], user_type, pts)
    except Exception as exc:
        ud["buf"] = ""
        await say(
            update,
            f"❌ Play failed:\n{short_err(exc)}\n\n🎯 Try again ({MIN_POINTS}-{MAX_POINTS})",
            InlineKeyboardMarkup(points_rows()),
        )
        return
    clear_state(ud)
    add_play(uid)

    data = resp.get("data") or {}
    if not isinstance(data, dict):
        data = {"data": data}
    lucky = bool(data.get("luckuser"))
    out = [
        "🎉 PLAY RESULT",
        f"📞 Number : {mobile}",
        f"💬 Message: {resp.get('message') or '(none)'}",
        f"🎯 Points : {pts}",
    ]
    if data.get("epay") is not None:
        out.append(f"💸 E-pay  : ₹{data['epay']}")
    out.append(f"🍀 Lucky  : {'YES ★' if lucky else 'no'}")
    extra = {k: v for k, v in data.items() if k not in ("epay", "luckuser")}
    if extra:
        out.append("➕ Extra  : " + json.dumps(extra))

    try:
        post = await asyncio.to_thread(api_fetch_profile, entry["token"])
        if post.get("rotated_token"):
            await asyncio.to_thread(update_token, uid, mobile, post["rotated_token"])
        pd = post.get("decrypted")
        if isinstance(pd, dict) and pd.get("epay_balance") is not None:
            out.append(f"💰 New e-pay balance: ₹{pd['epay_balance']}")
    except Exception as exc:
        log.warning("post-play profile failed: %s", exc)

    await say(update, "\n".join(out), after_play_markup())


# --------------------------------------------------------------------------- #
# Admin screens
# --------------------------------------------------------------------------- #
async def screen_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    clear_state(context.user_data)
    users = load_users()
    banned = sum(1 for u in users.values() if u.get("banned"))
    plays = sum(int(u.get("plays", 0)) for u in users.values())
    text = (
        "🛠 Admin Panel\n\n"
        f"👥 Users: {len(users)}\n"
        f"🚫 Banned: {banned}\n"
        f"📂 Saved numbers (all users): {total_saved_numbers()}\n"
        f"🎲 Total plays: {plays}\n\n"
        "Commands: /ban <id|@username>   /unban <id|@username>"
    )
    await say(update, text, InlineKeyboardMarkup([
        [btn("👥 All Users", "a:ul:all:0", "primary"), btn("🚫 Banned", "a:ul:ban:0", "danger")],
        [btn("⬅️ Back", "m:menu", "danger")],
    ]))


async def screen_users(update: Update, context: ContextTypes.DEFAULT_TYPE,
                       filt: str = "all", page: int = 0) -> None:
    users = list(load_users().values())
    if filt == "ban":
        users = [u for u in users if u.get("banned")]
    users.sort(key=lambda u: u.get("last_seen", ""), reverse=True)

    pages = max(1, (len(users) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    chunk = users[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]

    rows = [[btn(user_label(u), f"a:u:{u['id']}", "danger" if u.get("banned") else "primary")]
            for u in chunk]
    nav = []
    if page > 0:
        nav.append(btn("◀️ Prev", f"a:ul:{filt}:{page - 1}", "primary"))
    nav.append(btn(f"{page + 1}/{pages}", "a:noop"))
    if page < pages - 1:
        nav.append(btn("Next ▶️", f"a:ul:{filt}:{page + 1}", "primary"))
    rows.append(nav)
    rows.append([
        btn("👥 All", "a:ul:all:0", "success" if filt == "all" else "primary"),
        btn("🚫 Banned", "a:ul:ban:0", "success" if filt == "ban" else "primary"),
    ])
    rows.append([btn("⬅️ Back", "a:menu", "danger")])

    title = "🚫 Banned users" if filt == "ban" else "👥 All users"
    body = f"{title} ({len(users)})\nSorted by last activity. Tap a user to manage."
    if not users:
        body = f"{title}\n\nNo users here yet."
    await say(update, body, InlineKeyboardMarkup(rows))


def user_detail(rec: dict) -> tuple[str, InlineKeyboardMarkup]:
    uid = rec["id"]
    status = "🚫 Banned" if rec.get("banned") else "🟢 Active"
    if is_admin_id(uid):
        status += " (admin)"
    text = (
        f"👤 {user_html(rec)}\n"
        f"🆔 <code>{uid}</code>\n"
        f"📌 Status: {status}\n"
        f"📅 First seen: {short_dt(rec.get('first_seen'))}\n"
        f"🕒 Last seen: {short_dt(rec.get('last_seen'))}\n"
        f"📂 Saved numbers: {len(load_sessions(uid))}\n"
        f"🎲 Plays: {rec.get('plays', 0)}"
    )
    rows = []
    if not is_admin_id(uid):
        if rec.get("banned"):
            rows.append([btn("✅ Unban", f"a:ub:{uid}", "success")])
        else:
            rows.append([btn("🚫 Ban", f"a:b:{uid}", "danger")])
    if rec.get("username"):
        rows.append([InlineKeyboardButton("👤 Open profile", url=f"https://t.me/{rec['username']}")])
    rows.append([btn("⬅️ Back", "a:ul:all:0", "danger")])
    return text, InlineKeyboardMarkup(rows)


async def screen_user(update: Update, context: ContextTypes.DEFAULT_TYPE, uid: int) -> None:
    rec = get_user(uid)
    if not rec:
        await say(update, "User not found.",
                  InlineKeyboardMarkup([[btn("⬅️ Back", "a:ul:all:0", "danger")]]))
        return
    text, markup = user_detail(rec)
    await say(update, text, markup, html_mode=True)


async def apply_ban(context: ContextTypes.DEFAULT_TYPE, uid: int, flag: bool) -> Optional[dict]:
    if is_admin_id(uid):
        return None
    rec = set_banned(uid, flag)
    if not rec:
        return None
    if flag:
        state = context.application.user_data.get(uid)
        if state is not None:
            clear_state(state)
    try:
        await context.bot.send_message(
            uid, "🚫 You have been banned from this bot." if flag
            else "✅ You have been unbanned. Send /start to continue."
        )
    except Exception:
        pass
    return rec


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await gate(update, context):
        await screen_menu(update, context)


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await gate(update, context):
        await screen_menu(update, context)


async def cmd_sessions(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await gate(update, context):
        await screen_sessions(update, context)


async def cmd_login(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await gate(update, context):
        return
    mobile = norm_mobile(" ".join(context.args) if context.args else "")
    if not mobile:
        await update.message.reply_text("Usage: /login 9876543210")
        return
    clear_state(context.user_data)
    await submit_mobile(update, context, mobile)


async def cmd_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await gate(update, context) and is_admin_id(uid_of(update)):
        await screen_admin(update, context)


async def _ban_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE, flag: bool) -> None:
    if not (await gate(update, context) and is_admin_id(uid_of(update))):
        return
    verb = "ban" if flag else "unban"
    if not context.args:
        await update.message.reply_text(f"Usage: /{verb} <id|@username>")
        return
    rec = find_user(context.args[0])
    if not rec:
        await update.message.reply_text("User not found (they must have started the bot).")
        return
    if is_admin_id(rec["id"]):
        await update.message.reply_text("Can't ban an admin.")
        return
    rec = await apply_ban(context, rec["id"], flag)
    await update.message.reply_text(
        f"{'🚫 Banned' if flag else '✅ Unbanned'}: {user_html(rec)}",
        parse_mode="HTML", link_preview_options=NO_PREVIEW,
    )


async def cmd_ban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _ban_cmd(update, context, True)


async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _ban_cmd(update, context, False)


async def on_admin_button(update: Update, context: ContextTypes.DEFAULT_TYPE, data: str) -> None:
    q = update.callback_query
    parts = data.split(":")
    action = parts[1] if len(parts) > 1 else ""

    if action == "noop":
        await q.answer()
    elif action == "menu":
        await q.answer()
        await screen_admin(update, context)
    elif action == "ul":
        await q.answer()
        await screen_users(update, context, parts[2], int(parts[3]))
    elif action == "u":
        await q.answer()
        await screen_user(update, context, int(parts[2]))
    elif action in ("b", "ub"):
        target = int(parts[2])
        rec = await apply_ban(context, target, action == "b")
        await q.answer("Done" if rec else "Not allowed / not found")
        await screen_user(update, context, target)
    else:
        await q.answer()


async def on_button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q or not q.from_user:
        return
    if not await gate(update, context):
        return
    uid = q.from_user.id
    ud = context.user_data
    data = q.data or ""
    state = ud.get("state")

    # ---- admin ------------------------------------------------------------ #
    if data.startswith("a:"):
        if not is_admin_id(uid):
            await q.answer("Admins only", show_alert=True)
            return
        await on_admin_button(update, context, data)
        return

    # ---- navigation ------------------------------------------------------- #
    if data == "m:menu":
        await q.answer()
        await screen_menu(update, context)
        return
    if data == "m:help":
        await q.answer()
        await screen_help(update, context)
        return
    if data == "m:sess":
        await q.answer()
        await screen_sessions(update, context)
        return
    if data == "m:new":
        await q.answer()
        clear_state(ud)
        ud.update(state="mobile", buf="")
        await screen_input(update, context)
        return
    if data == "b:back":
        await q.answer()
        if state == "otp":
            ud.pop("sess", None)
            ud.update(state="mobile", buf=ud.get("mobile", ""))
            await screen_input(update, context)
        else:
            await screen_menu(update, context)
        return
    if data.startswith("s:"):
        await q.answer()
        clear_state(ud)
        await prepare_play(update, context, data[2:])
        return

    # ---- keypad / presets (need an active input state) -------------------- #
    if state not in MAX_LEN:
        await q.answer("This panel expired — opening menu")
        await screen_menu(update, context)
        return

    buf = ud.get("buf", "")

    if data.startswith("p:") and state == "points":
        await q.answer()
        ud["buf"] = data[2:]
        await screen_input(update, context)
        return

    if data.startswith("k:"):
        key = data[2:]
        if key.isdigit():
            await q.answer()
            if len(buf) < MAX_LEN[state]:
                ud["buf"] = buf + key
                await screen_input(update, context)
            return
        if key == "del":
            await q.answer()
            ud["buf"] = buf[:-1]
            await screen_input(update, context)
            return
        if key == "clr":
            await q.answer()
            ud["buf"] = ""
            await screen_input(update, context)
            return
        if key == "ok":
            if state == "mobile":
                mobile = norm_mobile(buf)
                if not mobile:
                    await q.answer("Enter a valid 10-digit mobile number", show_alert=True)
                    return
                await q.answer()
                await submit_mobile(update, context, mobile)
            elif state == "otp":
                if not re.fullmatch(r"\d{4,8}", buf):
                    await q.answer("Enter the OTP first", show_alert=True)
                    return
                await q.answer()
                await submit_otp(update, context, buf)
            elif state == "points":
                if not buf.isdigit() or not (MIN_POINTS <= int(buf) <= MAX_POINTS):
                    await q.answer(f"Points must be {MIN_POINTS}-{MAX_POINTS}", show_alert=True)
                    return
                await q.answer()
                await submit_points(update, context, int(buf))
            return

    await q.answer()


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.message.text:
        return
    if not await gate(update, context):
        return
    text = update.message.text.strip()
    ud = context.user_data
    state = ud.get("state")

    if state == "otp":
        if not re.fullmatch(r"\d{4,8}", text):
            await update.message.reply_text("Send the OTP digits only (or tap ⬅️ Back).")
            return
        try:
            await update.message.delete()  # remove OTP from chat
        except Exception:
            pass
        await submit_otp(update, context, text)
        return

    if state == "points":
        if not text.isdigit() or not (MIN_POINTS <= int(text) <= MAX_POINTS):
            await update.message.reply_text(f"Send points between {MIN_POINTS} and {MAX_POINTS}.")
            return
        await submit_points(update, context, int(text))
        return

    # idle or mobile entry
    mobile = norm_mobile(text)
    if mobile:
        clear_state(ud)
        await submit_mobile(update, context, mobile)
        return
    digits = re.sub(r"\D", "", text)
    if digits:
        ud.update(state="mobile", buf=digits[:10])
        await screen_input(update, context)
        return
    await screen_menu(update, context)


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("Unhandled error", exc_info=context.error)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set")
    if not ADMIN_IDS:
        raise SystemExit("ADMIN_ID is not set (your numeric Telegram user ID)")

    _ensure_session_dir()
    log.info("Sessions: %s | Users: %s | admins: %s", SESSION_FILE, USERS_FILE, sorted(ADMIN_IDS))

    app = Application.builder().token(BOT_TOKEN).concurrent_updates(True).build()
    private = filters.ChatType.PRIVATE
    app.add_handler(CommandHandler("start", cmd_start, filters=private))
    app.add_handler(CommandHandler("cancel", cmd_cancel, filters=private))
    app.add_handler(CommandHandler("login", cmd_login, filters=private))
    app.add_handler(CommandHandler("sessions", cmd_sessions, filters=private))
    app.add_handler(CommandHandler("admin", cmd_admin, filters=private))
    app.add_handler(CommandHandler("ban", cmd_ban, filters=private))
    app.add_handler(CommandHandler("unban", cmd_unban, filters=private))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND & private, on_text))
    app.add_error_handler(on_error)
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
