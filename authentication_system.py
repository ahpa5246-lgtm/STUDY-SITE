#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""STUDY-SITE / Authentication Homework — all application code in ONE Python file.

A working, offline desktop authentication application (Tkinter + SQLite).
No pip packages, cloud account, API key, or server required.

QUICK START
    python authentication_system.py                # GUI (if display available)
    python authentication_system.py --cli          # interactive terminal UI
    python authentication_system.py --demo         # automatic correct/wrong login
    python authentication_system.py --self-test    # run built-in security tests
    python authentication_system.py --db ./my.sqlite3 --cli

The SQLite database is created when first needed at:
    ~/.study_site_auth/accounts.sqlite3
This is a separate *data* file; every line of application and test code is here.

HOMEWORK CONTRACT
    Correct username + password -> "Grant Access"
    Incorrect credentials       -> "Wrong Credentials"

Security choices:
- Passwords are salted, memory-hard scrypt hashes; never stored in plaintext.
- SQL always uses bound parameters; usernames are unique case-insensitively.
- Failed logins are limited with a temporary account lockout.
- Password resets require a strong one-time recovery code issued at registration.
- Changing a password requires the current password.
- Generic authentication errors avoid revealing if a username exists.
- Local audit trail excludes passwords and recovery codes.
- No default administrator, hardcoded user, internet access, or insecure reset.

This is a locally stored desktop program, NOT a remote/web identity provider.
A production internet-facing service additionally needs a trusted backend, TLS,
server-side sessions, abuse protection, verified recovery, backups, and monitoring.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


APP_TITLE = "AccessLab | Authentication System"
SCHEMA_VERSION = 1
MIN_PASSWORD = 12
MAX_PASSWORD = 128
MAX_ATTEMPTS = 5
LOCK_SECONDS = 60
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
HASH_LENGTH = 32
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")
DEFAULT_DB = Path.home() / ".study_site_auth" / "accounts.sqlite3"
COMMON_PASSWORDS = {
    "password1234", "password12345", "123456789012", "123456789123",
    "qwerty123456", "letmein123456", "admin12345678", "iloveyou12345",
}


class AuthError(Exception):
    """Safe message that can be displayed to a local user."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def check_username(username: str) -> str:
    if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
        raise AuthError("User ID must be 3-32 letters, numbers, underscores, dots or hyphens.")
    return username


def check_password_strength(password: str, username: str = "") -> None:
    # Length-first passphrases; no arbitrary mandatory symbol/case requirements.
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise AuthError(f"Password must contain at least {MIN_PASSWORD} characters.")
    if len(password) > MAX_PASSWORD or len(password.encode("utf-8")) > 1024:
        raise AuthError("Password is too long.")
    if not password.strip():
        raise AuthError("Password cannot contain only whitespace.")
    if password.casefold() in COMMON_PASSWORDS:
        raise AuthError("Choose a less common password.")
    if username and username.casefold() in password.casefold():
        raise AuthError("Do not include your User ID in your password.")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=HASH_LENGTH)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt, digest = stored.split("$")
        if algorithm != "scrypt":
            return False
        # Do not trust adjustable work factors from a compromised database.
        if (int(n), int(r), int(p)) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
            return False
        raw_salt, expected = bytes.fromhex(salt), bytes.fromhex(digest)
        if len(raw_salt) != 16 or len(expected) != HASH_LENGTH:
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=raw_salt,
                                n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=HASH_LENGTH)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, OverflowError, UnicodeError):
        return False


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuthResult:
    success: bool
    message: str
    username: Optional[str] = None


class AuthStore:
    """Local credential service. Call methods, not SQLite directly, from the UI."""

    def __init__(self, db_path: Path | str = DEFAULT_DB):
        self.path = Path(db_path).expanduser().resolve()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            try:
                self.path.parent.chmod(0o700)
            except OSError:
                pass
        # The dummy hash makes nonexistent-user checks cost similar to real ones.
        self._dummy_hash = hash_password("unregistered-user-dummy-value-27")
        self.conn = sqlite3.connect(str(self.path), timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                recovery_digest TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE INDEX IF NOT EXISTS audit_by_user ON audit(user_id, id DESC);
        """)
        if os.name == "posix":
            try:
                self.path.chmod(0o600)
            except OSError:
                pass

    def __enter__(self) -> "AuthStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    def _user(self, username: str) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    def _audit(self, user_id: int, action: str) -> None:
        self.conn.execute("INSERT INTO audit (user_id,action,occurred_at) VALUES (?,?,?)",
                          (user_id, action, utc_now()))

    def register(self, username: str, password: str) -> str:
        """Create account; RETURN recovery code once. Caller must display/save it."""
        username = check_username(username)
        check_password_strength(password, username)
        password_hash = hash_password(password)
        recovery_code = secrets.token_urlsafe(24)
        now = utc_now()
        try:
            with self.conn:
                cur = self.conn.execute(
                    "INSERT INTO users(username,password_hash,recovery_digest,created_at,updated_at) "
                    "VALUES (?,?,?,?,?)",
                    (username, password_hash, token_digest(recovery_code), now, now),
                )
                self._audit(cur.lastrowid, "register")
        except sqlite3.IntegrityError as exc:
            raise AuthError("This User ID is already taken.") from exc
        return recovery_code

    def login(self, username: str, password: str) -> AuthResult:
        """Only grant on verified password and unlocked user."""
        if not isinstance(username, str):
            username = ""
        if not isinstance(password, str):
            password = ""
        row = self._user(username) if USERNAME_PATTERN.fullmatch(username) else None
        # Guard scrypt against unbounded hostile input and preserve generic errors.
        if len(password) > MAX_PASSWORD or len(password.encode("utf-8")) > 1024:
            return AuthResult(False, "Wrong Credentials")
        if row is None:
            verify_password(password, self._dummy_hash)
            return AuthResult(False, "Wrong Credentials")
        now_epoch = int(time.time())
        if row["locked_until"] > now_epoch:
            verify_password(password, self._dummy_hash)
            with self.conn:
                self._audit(row["id"], "blocked_login")
            return AuthResult(False, "Wrong Credentials")
        matched = verify_password(password, row["password_hash"])
        with self.conn:
            if matched:
                self.conn.execute(
                    "UPDATE users SET failed_attempts=0,locked_until=0,last_login_at=? WHERE id=?",
                    (utc_now(), row["id"]),
                )
                self._audit(row["id"], "login_success")
                return AuthResult(True, "Grant Access", row["username"])
            # A lockout is time-limited; it never permanently blocks the account.
            attempts = (row["failed_attempts"] if row["locked_until"] == 0 else 0) + 1
            locked_until = now_epoch + LOCK_SECONDS if attempts >= MAX_ATTEMPTS else 0
            self.conn.execute(
                "UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?",
                (0 if locked_until else attempts, locked_until, row["id"]),
            )
            self._audit(row["id"], "login_locked" if locked_until else "login_failure")
        return AuthResult(False, "Wrong Credentials")

    def change_password(self, username: str, current: str, new: str) -> None:
        row = self._user(username)
        if not row or not verify_password(current, row["password_hash"]):
            raise AuthError("Wrong Credentials")
        check_password_strength(new, row["username"])
        if verify_password(new, row["password_hash"]):
            raise AuthError("New password must be different from the current one.")
        updated = hash_password(new)
        with self.conn:
            self.conn.execute(
                "UPDATE users SET password_hash=?,failed_attempts=0,locked_until=0,updated_at=? WHERE id=?",
                (updated, utc_now(), row["id"]),
            )
            self._audit(row["id"], "password_changed")

    def recover(self, username: str, recovery_code: str, new_password: str) -> str:
        """Reset with original code; rotate the code upon success, even during lockout."""
        row = self._user(username) if isinstance(username, str) else None
        candidate = token_digest(recovery_code) if isinstance(recovery_code, str) else ""
        if not row or not hmac.compare_digest(candidate, row["recovery_digest"]):
            raise AuthError("Invalid User ID or recovery code.")
        check_password_strength(new_password, row["username"])
        new_code = secrets.token_urlsafe(24)
        updated = hash_password(new_password)
        with self.conn:
            self.conn.execute(
                "UPDATE users SET password_hash=?,recovery_digest=?,failed_attempts=0,"
                "locked_until=0,updated_at=? WHERE id=?",
                (updated, token_digest(new_code), utc_now(), row["id"]),
            )
            self._audit(row["id"], "account_recovered")
        return new_code

    def profile(self, username: str) -> dict[str, str | None]:
        row = self._user(username)
        if row is None:
            raise AuthError("User not found.")
        return {"username": row["username"], "created": row["created_at"],
                "last_login": row["last_login_at"]}

    def activity(self, username: str, limit: int = 8) -> list[tuple[str, str]]:
        row = self._user(username)
        if row is None:
            raise AuthError("User not found.")
        records = self.conn.execute(
            "SELECT action,occurred_at FROM audit WHERE user_id=? ORDER BY id DESC LIMIT ?",
            (row["id"], max(1, min(50, limit))),
        ).fetchall()
        return [(item["action"], item["occurred_at"]) for item in records]


def terminal_app(store: AuthStore) -> None:
    session: Optional[str] = None
    print("\n" + "=" * 56)
    print(" ACCESSLAB  |  Secure Authentication Homework")
    print("=" * 56)
    print("Offline • SQLite • scrypt • No third-party packages")
    while True:
        try:
            if session:
                print(f"\nSigned in as: {session}")
                print("1) My account  2) Change password  3) Logout  0) Exit")
                option = input("Choose: ").strip()
                if option == "1":
                    info = store.profile(session)
                    print(f"Created: {info['created']} | Last login: {info['last_login']}")
                    print("Recent activity:")
                    for action, at in store.activity(session):
                        print(f"  {at}  {action}")
                elif option == "2":
                    old = getpass.getpass("Current password: ")
                    new = getpass.getpass("New password: ")
                    confirm = getpass.getpass("Confirm new password: ")
                    if new != confirm:
                        print("Passwords do not match.")
                    else:
                        store.change_password(session, old, new)
                        print("Password changed successfully.")
                elif option == "3":
                    session = None
                    print("Logged out.")
                elif option == "0":
                    break
                else:
                    print("Choose a listed option.")
            else:
                print("\n1) Login  2) Register  3) Recover account  0) Exit")
                option = input("Choose: ").strip()
                if option == "1":
                    username = input("User ID: ").strip()
                    password = getpass.getpass("Password: ")
                    result = store.login(username, password)
                    print("\n" + result.message)
                    if result.success:
                        session = result.username
                elif option == "2":
                    username = input("Choose User ID: ").strip()
                    password = getpass.getpass("Choose password (12+ characters): ")
                    confirm = getpass.getpass("Confirm password: ")
                    if password != confirm:
                        print("Passwords do not match.")
                        continue
                    code = store.register(username, password)
                    print("Account created. Store this ONE-TIME recovery code safely:")
                    print(code)
                    print("Anyone with this code can reset the account password.")
                elif option == "3":
                    username = input("User ID: ").strip()
                    code = getpass.getpass("Recovery code: ")
                    new_pass = getpass.getpass("New password: ")
                    confirm = getpass.getpass("Confirm new password: ")
                    if new_pass != confirm:
                        print("Passwords do not match.")
                        continue
                    new_code = store.recover(username, code, new_pass)
                    print("Password reset. Save your REPLACEMENT recovery code:")
                    print(new_code)
                elif option == "0":
                    break
                else:
                    print("Choose a listed option.")
        except AuthError as exc:
            print("Error:", exc)
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break


def graphical_app(store: AuthStore) -> None:
    """Responsive, self-contained Tkinter GUI; no pip dependencies or external assets.

    Visual architecture follows modern documented widget/layout patterns, while
    keeping the SQLite-backed authentication logic untouched.
    """
    import tkinter as tk
    from tkinter import messagebox

    P = {
        "ink": "#0C1426", "hero": "#0D1527", "hero_panel": "#14233A",
        "mint": "#52DBB9", "mint_hover": "#42CCA9", "mint_dark": "#06745D",
        "hero_text": "#F7FAFF", "hero_muted": "#94A5BB",
        "canvas_line": "#1E314B", "back": "#F5F7FB", "white": "#FFFFFF",
        "text": "#172238", "muted": "#77839A", "border": "#DDE4EE",
        "field": "#F8FAFD", "red": "#B84B55", "red_back": "#FFF0F1",
        "green_back": "#E8F8F0", "button_dark": "#112037",
    }
    FONT = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
    FONT_MONO = "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"
    root = tk.Tk()
    root.title(APP_TITLE)
    root.geometry("1160x750")
    root.minsize(930, 670)
    root.configure(bg=P["back"])
    root.grid_columnconfigure(0, weight=43, uniform="page")
    root.grid_columnconfigure(1, weight=57, uniform="page")
    root.grid_rowconfigure(0, weight=1)
    # Keep the Windows and Linux scaling behavior reasonable.
    root.option_add("*Font", f"{{{FONT}}} 10")
    active_user: Optional[str] = None
    hero = tk.Canvas(root, bg=P["hero"], borderwidth=0, highlightthickness=0)
    hero.grid(row=0, column=0, sticky="nsew")
    content = tk.Frame(root, bg=P["back"])
    content.grid(row=0, column=1, sticky="nsew")

    def hero_draw(event: object = None) -> None:
        """Subtle geometric graphic; drawn from code, not an image download."""
        w, h = hero.winfo_width(), hero.winfo_height()
        if w < 10 or h < 10:
            return
        hero.delete("all")
        hero.create_rectangle(0, 0, w, h, fill=P["hero"], outline="")
        for dx in range(40, w, 29):
            for dy in range(245, h - 62, 29):
                if (dx + 2 * dy) % 5 != 0:
                    hero.create_oval(dx, dy, dx + 2, dy + 2,
                                     fill="#1A2B43", outline="")
        cx, cy = w * 0.82, h * 0.71
        for radius in (142, 204, 269):
            hero.create_oval(cx - radius, cy - radius, cx + radius,
                             cy + radius, outline=P["canvas_line"], width=1)
        hero.create_arc(cx - 204, cy - 204, cx + 204, cy + 204,
                        start=33, extent=46, outline=P["mint"], width=3, style="arc")
        hero.create_oval(cx - 6, cy - 6, cx + 6, cy + 6,
                         fill=P["mint"], outline="")
        x = max(38, min(62, w * 0.1))
        hero.create_rectangle(x, 44, x + 38, 82, fill=P["mint"], outline="")
        hero.create_text(x + 19, 63, text="A", font=(FONT, 18, "bold"),
                         fill=P["hero"], anchor="center")
        hero.create_text(x + 51, 56, text="ACCESSLAB", anchor="w",
                         font=(FONT, 14, "bold"), fill=P["hero_text"])
        hero.create_text(x + 52, 76, text="IDENTITY  /  LOCAL SYSTEM", anchor="w",
                         font=(FONT, 8, "bold"), fill=P["hero_muted"])
        hero.create_line(x, 115, w - x, 115, fill=P["canvas_line"])
        title_y = max(182, h * .30)
        hero.create_text(x, title_y, text="YOUR SPACE.", anchor="nw",
                         font=(FONT, 11, "bold"), fill=P["mint"])
        size = 35 if w >= 440 else 30
        hero.create_text(x - 2, title_y + 40,
                         text="Privacy starts\nwith a sign in.", anchor="nw",
                         font=(FONT, size, "bold"), fill=P["hero_text"],
                         width=w - x - 24)
        hero.create_text(x, title_y + 192,
                         text="A private desktop workspace. Your credentials\nare verified locally and never leave this device.",
                         font=(FONT, 10), fill=P["hero_muted"], anchor="nw",
                         width=w - x - 36)
        hero.create_line(x, h - 138, w - x, h - 138, fill=P["canvas_line"])
        hero.create_oval(x, h - 104, x + 8, h - 96,
                         fill=P["mint"], outline="")
        hero.create_text(x + 18, h - 100, text="LOCAL FIRST", anchor="w",
                         font=(FONT, 9, "bold"), fill=P["hero_text"])
        hero.create_text(x, h - 75,
                         text="SQLite   /   SCRYPT   /   NO CLOUD REQUIRED",
                         font=(FONT, 8), fill=P["hero_muted"], anchor="w")
        hero.create_text(w - x, h - 39, text="ACCESSLAB  —  2026",
                         font=(FONT, 8), fill=P["hero_muted"], anchor="e")

    hero.bind("<Configure>", hero_draw)

    def lbl(parent: tk.Misc, text: str, size: int = 10, color: str = "text",
            bold: bool = False, **kwargs: object) -> tk.Label:
        return tk.Label(parent, text=text, bg=P["white"], fg=P.get(color, color),
                        font=(FONT, size, "bold" if bold else "normal"),
                        anchor="w", justify="left", **kwargs)

    def round_rect(canvas: tk.Canvas, x1: int, y1: int, x2: int, y2: int,
                   radius: int, fill: str, outline: str = "") -> None:
        r = min(radius, int((y2 - y1) / 2), int((x2 - x1) / 2))
        # Tk smooth polygon supports corners without extra imports/assets.
        points = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
                  x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
                  x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        canvas.create_polygon(points, fill=fill, outline=outline,
                              smooth=True, splinesteps=12)

    class Action(tk.Canvas):
        def __init__(self, parent: tk.Misc, text: str, command: object,
                     kind: str = "primary", height: int = 48) -> None:
            self.kind, self.label, self.handler, self.hover = kind, text, command, False
            super().__init__(parent, height=height, width=350, bg=P["white"],
                             highlightthickness=0, borderwidth=0, cursor="hand2",
                             takefocus=True)
            self.bind("<Configure>", self.paint)
            self.bind("<Enter>", lambda _e: self.set_hover(True))
            self.bind("<Leave>", lambda _e: self.set_hover(False))
            self.bind("<Button-1>", lambda _e: self.invoke())
            self.bind("<Return>", lambda _e: self.invoke())
            self.bind("<space>", lambda _e: self.invoke())
            self.bind("<FocusIn>", self.paint)
            self.bind("<FocusOut>", self.paint)

        def set_hover(self, state: bool) -> None:
            self.hover = state
            self.paint()

        def invoke(self) -> None:
            self.handler()

        def paint(self, _event: object = None) -> None:
            w, h = self.winfo_width(), self.winfo_height()
            if w <= 5 or h <= 5:
                return
            self.delete("all")
            if self.kind == "primary":
                bg = P["mint_hover"] if self.hover else P["mint"]
                fg = P["ink"]
            elif self.kind == "dark":
                bg = "#1E304C" if self.hover else P["button_dark"]
                fg = P["white"]
            else:
                bg = "#F4F8FC" if self.hover else P["white"]
                fg = P["text"]
            round_rect(self, 1, 1, w - 1, h - 1, 11, bg,
                       P["border"] if self.kind == "secondary" else "")
            self.create_text(w / 2, h / 2, text=self.label,
                             font=(FONT, 10, "bold"), fill=fg, anchor="center")
            if self.focus_get() is self:
                self.create_rectangle(4, 4, w - 5, h - 5, outline=P["mint_dark"])

    def link(parent: tk.Misc, text: str, fn: object,
             align: str = "w") -> tk.Label:
        widget = lbl(parent, text, 10, "mint_dark", True, cursor="hand2")
        widget.configure(anchor=align)
        widget.bind("<Button-1>", lambda _e: fn())
        widget.bind("<Enter>", lambda _e: widget.configure(fg="#0A9D7A"))
        widget.bind("<Leave>", lambda _e: widget.configure(fg=P["mint_dark"]))
        return widget

    def field(parent: tk.Misc, title: str, secret: bool = False,
              compact: bool = False) -> tk.Entry:
        group = tk.Frame(parent, bg=P["white"])
        group.pack(fill="x", pady=(0, 9 if compact else 17))
        lbl(group, title, 9, "text", True).pack(fill="x", pady=(0, 7))
        border = tk.Frame(group, bg=P["border"], padx=1, pady=1)
        border.pack(fill="x")
        inside = tk.Frame(border, bg=P["field"], height=50)
        inside.pack(fill="x")
        inside.pack_propagate(False)
        entry = tk.Entry(inside, bd=0, relief="flat", bg=P["field"],
                         fg=P["text"], insertbackground=P["text"],
                         font=(FONT, 11), highlightthickness=0, show="•" if secret else "")
        entry.pack(side="left", fill="both", expand=True, padx=(15, 7), pady=12)
        if secret:
            shown = tk.BooleanVar(value=False)
            toggle = tk.Label(inside, text="SHOW", bg=P["field"],
                              fg=P["mint_dark"], cursor="hand2",
                              font=(FONT, 8, "bold"), padx=12)
            toggle.pack(side="right")
            def switch(_event: object = None) -> None:
                shown.set(not shown.get())
                entry.config(show="" if shown.get() else "•")
                toggle.config(text="HIDE" if shown.get() else "SHOW")
            toggle.bind("<Button-1>", switch)
        entry.bind("<FocusIn>", lambda _e: border.configure(bg=P["mint_dark"]))
        entry.bind("<FocusOut>", lambda _e: border.configure(bg=P["border"]))
        return entry

    # Header and footer remain static while the central card switches screens.
    header = tk.Frame(content, bg=P["back"])
    header.place(relx=1, x=-39, y=35, anchor="ne")
    tk.Label(header, text="PYTHON  /  DESKTOP EDITION", bg=P["back"],
             fg=P["muted"], font=(FONT, 9, "bold")).pack()
    footer = tk.Frame(content, bg=P["back"])
    footer.place(relx=.5, rely=1, y=-32, anchor="s")
    tk.Label(footer, text="ENCRYPTED CREDENTIALS      •      OFFLINE BY DESIGN",
             bg=P["back"], fg=P["muted"], font=(FONT, 8)).pack()
    panel: Optional[tk.Frame] = None

    def screen(kicker: str, title: str, subtitle: str,
               compact: bool = False) -> tk.Frame:
        nonlocal panel
        if panel is not None:
            panel.destroy()
        panel = tk.Frame(content, bg=P["white"], highlightthickness=1,
                         highlightbackground=P["border"], highlightcolor=P["border"])
        panel.place(relx=.5, rely=.48, anchor="center")
        body = tk.Frame(panel, width=390, bg=P["white"])
        body.pack(padx=42, pady=20 if compact else 32, fill="x")
        body.pack_propagate(True)
        lbl(body, kicker, 9, "mint_dark", True).pack(anchor="w", pady=(0, 10))
        lbl(body, title, 24, "text", True).pack(anchor="w", pady=(0, 5))
        lbl(body, subtitle, 10, "muted", wraplength=390).pack(anchor="w", pady=(0, 17 if compact else 29))
        return body

    def status(body: tk.Misc) -> tk.Label:
        outcome = lbl(body, "", 9, "red", wraplength=390)
        outcome.pack(fill="x", pady=(5, 10))
        return outcome

    def show_error(target: tk.Label, message: str) -> None:
        target.config(text=message, fg=P["red"])

    def primary(body: tk.Misc, text: str, fn: object,
                kind: str = "primary", pady: tuple[int, int] = (8, 0)) -> Action:
        control = Action(body, text, fn, kind)
        control.pack(fill="x", pady=pady)
        return control

    def login_screen() -> None:
        nonlocal active_user
        active_user = None
        body = screen("01  /  SECURE ACCESS", "Welcome back.",
                      "Enter your User ID and password to continue.")
        username = field(body, "USER ID")
        password = field(body, "PASSWORD", secret=True)
        tools = tk.Frame(body, bg=P["white"])
        tools.pack(fill="x", pady=(0, 4))
        link(tools, "Forgot password?", recover_screen).pack(side="right")
        outcome = status(body)
        def submit(_event: object = None) -> None:
            nonlocal active_user
            try:
                result = store.login(username.get().strip(), password.get())
                password.delete(0, "end")
                if result.success:
                    active_user = result.username
                    dashboard()
                else:
                    show_error(outcome, "Wrong Credentials  —  please try again.")
            except (AuthError, sqlite3.Error) as exc:
                show_error(outcome, f"Unable to authenticate: {exc}")
        password.bind("<Return>", submit)
        username.bind("<Return>", lambda _e: password.focus_set())
        primary(body, "Sign in   →", submit, pady=(6, 22))
        lbl(body, "NEW TO ACCESSLAB?", 8, "muted", True).pack(anchor="center")
        primary(body, "Create an account", register_screen, "secondary", (9, 0))
        username.focus_set()

    def register_screen() -> None:
        body = screen("02  /  GET STARTED", "Create an account.",
                      "One account, stored privately on this computer.")
        username = field(body, "CHOOSE A USER ID")
        password = field(body, "PASSWORD  •  AT LEAST 12 CHARACTERS", True)
        confirmation = field(body, "CONFIRM PASSWORD", True)
        outcome = status(body)
        def submit() -> None:
            try:
                if password.get() != confirmation.get():
                    raise AuthError("Passwords do not match.")
                code = store.register(username.get().strip(), password.get())
                recovery_code_screen(code, "Your account is ready.")
            except (AuthError, sqlite3.Error) as exc:
                show_error(outcome, str(exc))
        confirmation.bind("<Return>", lambda _e: submit())
        primary(body, "Create account   →", submit)
        link(body, "←  Back to sign in", login_screen).pack(anchor="center", pady=(19, 0))
        username.focus_set()

    def recovery_code_screen(code: str, message: str) -> None:
        body = screen("03  /  SAVE YOUR BACKUP", "Your recovery key.",
                      f"{message} This code is shown once. Store it somewhere safe.")
        lbl(body, "ONE-TIME RECOVERY CODE", 9, "text", True).pack(anchor="w", pady=(0, 9))
        holder = tk.Frame(body, bg=P["field"], highlightbackground=P["border"],
                          highlightthickness=1)
        holder.pack(fill="x")
        tk.Label(holder, text=code, bg=P["field"], fg=P["mint_dark"],
                 font=(FONT_MONO, 11, "bold"), anchor="w",
                 justify="left").pack(fill="x", padx=13, pady=17)
        tk.Label(body, text="Keep this code private; anyone with it can reset your password.",
                 bg=P["white"], fg=P["red"], font=(FONT, 9),
                 wraplength=388, anchor="w", justify="left").pack(fill="x", pady=(16, 12))
        def copy() -> None:
            root.clipboard_clear()
            root.clipboard_append(code)
            root.update_idletasks()
            messagebox.showinfo("Recovery key", "Code copied. Keep it somewhere safe.", parent=root)
        primary(body, "Copy recovery code", copy)
        primary(body, "I saved it  →  Sign in", login_screen, "secondary", (10, 0))

    def recover_screen() -> None:
        body = screen("04  /  ACCOUNT RECOVERY", "Reset your password.",
                      "Provide the recovery code you saved during registration.", compact=True)
        username = field(body, "USER ID", compact=True)
        code = field(body, "RECOVERY CODE", True, compact=True)
        password = field(body, "NEW PASSWORD", True, compact=True)
        confirm = field(body, "CONFIRM NEW PASSWORD", True, compact=True)
        outcome = status(body)
        def submit() -> None:
            try:
                if password.get() != confirm.get():
                    raise AuthError("Passwords do not match.")
                replacement = store.recover(username.get().strip(), code.get(), password.get())
                recovery_code_screen(replacement, "Your password has been reset.")
            except (AuthError, sqlite3.Error) as exc:
                show_error(outcome, str(exc))
        confirm.bind("<Return>", lambda _e: submit())
        primary(body, "Reset password   →", submit)
        link(body, "←  Back to sign in", login_screen).pack(anchor="center", pady=(17, 0))
        username.focus_set()

    def change_screen() -> None:
        if not active_user:
            login_screen()
            return
        body = screen("06  /  ACCOUNT SECURITY", "Change password.",
                      f"Signed in as {active_user}. Use a new, unique passphrase.")
        old = field(body, "CURRENT PASSWORD", True)
        new = field(body, "NEW PASSWORD", True)
        confirm = field(body, "CONFIRM NEW PASSWORD", True)
        outcome = status(body)
        def submit() -> None:
            try:
                if new.get() != confirm.get():
                    raise AuthError("Passwords do not match.")
                store.change_password(active_user, old.get(), new.get())
                dashboard()
            except (AuthError, sqlite3.Error) as exc:
                show_error(outcome, str(exc))
        confirm.bind("<Return>", lambda _e: submit())
        primary(body, "Update password   →", submit)
        link(body, "←  Back to overview", dashboard).pack(anchor="center", pady=(17, 0))
        old.focus_set()

    def dashboard() -> None:
        if not active_user:
            login_screen()
            return
        body = screen("05  /  AUTHENTICATED", "Grant Access ✓",
                      f"You're signed in as {active_user}. Your credentials were verified.")
        info = store.profile(active_user)
        rows = (("USER ID", info["username"] or ""),
                ("ACCOUNT CREATED", (info["created"] or "")[:19].replace("T", " ")),
                ("LAST LOGIN (UTC)", (info["last_login"] or "Never")[:19].replace("T", " ")))
        for label_text, value in rows:
            section = tk.Frame(body, bg=P["field"], padx=14, pady=9)
            section.pack(fill="x", pady=(0, 6))
            tk.Label(section, text=label_text, bg=P["field"], fg=P["muted"],
                     font=(FONT, 8, "bold")).pack(anchor="w")
            tk.Label(section, text=value, bg=P["field"], fg=P["text"],
                     font=(FONT, 10, "bold")).pack(anchor="w", pady=(3, 0))
        lbl(body, "RECENT ACTIVITY", 9, "text", True).pack(anchor="w", pady=(14, 7))
        records = store.activity(active_user, 4)
        for action, when in records:
            lbl(body, f"{action.replace('_', ' ').title()}     •     {when[:16].replace('T',' ')}",
                9, "muted").pack(anchor="w", pady=(0, 3))
        primary(body, "Change password", change_screen, "dark", (16, 0))
        primary(body, "Sign out", login_screen, "secondary", (9, 0))

    root.protocol("WM_DELETE_WINDOW", root.destroy)
    login_screen()
    root.mainloop()


def demo() -> None:
    """Run the assignment in a temporary database, leaving no permanent demo account."""
    with tempfile.TemporaryDirectory(prefix="accesslab_demo_") as folder:
        with AuthStore(Path(folder) / "demo.sqlite3") as store:
            store.register("Student2026", "Correct-Horse-Battery-2026!")
            good = store.login("Student2026", "Correct-Horse-Battery-2026!")
            wrong_password = store.login("Student2026", "incorrect-password")
            wrong_user = store.login("NotAStudent", "Correct-Horse-Battery-2026!")
            print("HOMEWORK: Authentication using User ID and Password")
            print("Correct ID + password: ", good.message)
            print("Wrong password:       ", wrong_password.message)
            print("Wrong ID:             ", wrong_user.message)
            assert good.message == "Grant Access"
            assert wrong_password.message == wrong_user.message == "Wrong Credentials"
            print("Demo passed. The temporary test database was removed.")


class AuthenticationTests(unittest.TestCase):
    """Built into this same file; run: python authentication_system.py --self-test"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="accesslab_test_")
        self.path = Path(self.tmp.name) / "test.db"
        self.store = AuthStore(self.path)
        self.original = "Never use a short password! 2050"
        self.recovery = self.store.register("StudentOne", self.original)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_homework_correct_credentials_grant_access(self) -> None:
        result = self.store.login("StudentOne", self.original)
        self.assertTrue(result.success)
        self.assertEqual(result.message, "Grant Access")

    def test_wrong_password_is_rejected(self) -> None:
        result = self.store.login("StudentOne", "A totally wrong password")
        self.assertFalse(result.success)
        self.assertEqual(result.message, "Wrong Credentials")

    def test_wrong_user_is_rejected_without_enumeration(self) -> None:
        self.assertEqual(self.store.login("UnknownUser", self.original).message, "Wrong Credentials")

    def test_case_insensitive_user_id(self) -> None:
        self.assertTrue(self.store.login("studentone", self.original).success)

    def test_duplicate_user_is_rejected(self) -> None:
        with self.assertRaises(AuthError):
            self.store.register("STUDENTONE", "A Different Secure Passphrase! 99")

    def test_short_password_is_rejected(self) -> None:
        with self.assertRaises(AuthError):
            self.store.register("AnotherUser", "short")

    def test_common_password_is_rejected(self) -> None:
        with self.assertRaises(AuthError):
            self.store.register("AnotherUser", "password1234")

    def test_username_inside_password_is_rejected(self) -> None:
        with self.assertRaises(AuthError):
            self.store.register("AnotherUser", "anotheruser12345678")

    def test_sql_injection_does_not_grant_access(self) -> None:
        self.assertFalse(self.store.login("' OR 1=1 --", "anything goes").success)
        self.assertFalse(self.store.login("StudentOne", "' OR '1'='1").success)

    def test_password_is_salted_and_not_plaintext(self) -> None:
        self.assertNotIn(self.original, self.store._user("StudentOne")["password_hash"])
        self.assertNotEqual(hash_password(self.original), hash_password(self.original))

    def test_bad_hash_is_rejected(self) -> None:
        self.assertFalse(verify_password(self.original, "scrypt$invalid"))

    def test_lockout_after_five_failures(self) -> None:
        for _ in range(MAX_ATTEMPTS):
            self.assertFalse(self.store.login("StudentOne", "wrong").success)
        self.assertGreater(self.store._user("StudentOne")["locked_until"], int(time.time()))
        self.assertFalse(self.store.login("StudentOne", self.original).success)

    def test_lockout_expiry_allows_correct_login(self) -> None:
        for _ in range(MAX_ATTEMPTS):
            self.store.login("StudentOne", "wrong")
        with self.store.conn:
            self.store.conn.execute("UPDATE users SET locked_until=? WHERE username=?",
                                    (int(time.time()) - 1, "StudentOne"))
        self.assertTrue(self.store.login("StudentOne", self.original).success)

    def test_successful_login_resets_attempt_counter(self) -> None:
        self.store.login("StudentOne", "wrong")
        self.assertTrue(self.store.login("StudentOne", self.original).success)
        self.assertEqual(self.store._user("StudentOne")["failed_attempts"], 0)

    def test_password_change_requires_old_password(self) -> None:
        with self.assertRaises(AuthError):
            self.store.change_password("StudentOne", "wrong", "A new long safe password! 99")
        self.assertTrue(self.store.login("StudentOne", self.original).success)

    def test_change_password_invalidates_old_password(self) -> None:
        new = "A new long safe password! 99"
        self.store.change_password("StudentOne", self.original, new)
        self.assertFalse(self.store.login("StudentOne", self.original).success)
        self.assertTrue(self.store.login("StudentOne", new).success)

    def test_account_recovery_and_code_rotation(self) -> None:
        new = "A freshly recovered password 2026!"
        replacement = self.store.recover("StudentOne", self.recovery, new)
        self.assertNotEqual(self.recovery, replacement)
        self.assertFalse(self.store.login("StudentOne", self.original).success)
        self.assertTrue(self.store.login("StudentOne", new).success)
        with self.assertRaises(AuthError):
            self.store.recover("StudentOne", self.recovery, "Another long secure phrase 99")

    def test_recovery_invalid_code_does_not_change_password(self) -> None:
        with self.assertRaises(AuthError):
            self.store.recover("StudentOne", "wrong", "Another long secure phrase 99")
        self.assertTrue(self.store.login("StudentOne", self.original).success)

    def test_recovery_unlocks_account(self) -> None:
        for _ in range(MAX_ATTEMPTS):
            self.store.login("StudentOne", "wrong")
        new = "Recovered password after lock 2026!"
        self.store.recover("StudentOne", self.recovery, new)
        self.assertTrue(self.store.login("StudentOne", new).success)

    def test_database_survives_reopening(self) -> None:
        with AuthStore(self.path) as another:
            self.assertTrue(another.login("StudentOne", self.original).success)

    def test_audit_never_contains_secret(self) -> None:
        self.store.login("StudentOne", "wrong")
        events = self.store.activity("StudentOne")
        self.assertTrue(any(action == "login_failure" for action, _ in events))
        dump = "".join(str(x) for x in events)
        self.assertNotIn(self.original, dump)
        self.assertNotIn(self.recovery, dump)

    def test_long_password_is_bounded(self) -> None:
        self.assertEqual(self.store.login("StudentOne", "X" * 400).message, "Wrong Credentials")

    def test_unicode_passphrase(self) -> None:
        self.store.register("ArabicUser", "كلمة مرور طويلة وآمنة للطالب ٢٠٢٦")
        self.assertTrue(self.store.login("ArabicUser", "كلمة مرور طويلة وآمنة للطالب ٢٠٢٦").success)


def run_tests() -> bool:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AuthenticationTests)
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite).wasSuccessful()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Full offline authentication homework in one standard-library Python file."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--cli", action="store_true", help="Open the terminal interface")
    group.add_argument("--gui", action="store_true", help="Open the desktop GUI")
    group.add_argument("--demo", action="store_true", help="Demonstrate correct/incorrect credentials")
    group.add_argument("--self-test", action="store_true", help="Run isolated automated security tests")
    parser.add_argument("--db", type=Path, default=Path(os.environ.get("AUTH_DB_PATH", DEFAULT_DB)),
                        help="SQLite database location (default: user home directory)")
    args = parser.parse_args(argv)
    if args.demo:
        demo()
        return 0
    if args.self_test:
        return 0 if run_tests() else 1
    try:
        with AuthStore(args.db) as store:
            if args.cli:
                terminal_app(store)
            elif args.gui:
                graphical_app(store)
            else:
                try:
                    graphical_app(store)
                except (ImportError, ModuleNotFoundError) as exc:
                    print(f"GUI unavailable ({exc}). Use --cli instead.", file=sys.stderr)
                    return 2
                except Exception as exc:
                    # Codespaces/headless Linux commonly lacks a display.
                    if type(exc).__name__ != "TclError":
                        raise
                    if sys.stdin.isatty():
                        print("No graphical display: using CLI instead.")
                        terminal_app(store)
                    else:
                        print("No display detected. Try --demo, --self-test or --cli.", file=sys.stderr)
                        return 2
        return 0
    except (sqlite3.Error, OSError) as exc:
        print(f"Storage error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())