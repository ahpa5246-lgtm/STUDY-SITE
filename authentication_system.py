#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.title(APP_TITLE)
    root.geometry("950x680")
    root.minsize(720, 600)
    root.configure(bg="#0b1324")
    root.option_add("*Font", "Arial 10")

    C = {"bg": "#0b1324", "panel": "#111d33", "field": "#182941",
         "muted": "#96a9c1", "white": "#f3f7ff", "accent": "#65e4c3",
         "line": "#293e59", "red": "#ff8e99", "gold": "#fad695"}
    active_user: Optional[str] = None
    outer = tk.Frame(root, bg=C["bg"])
    outer.pack(fill="both", expand=True, padx=35, pady=23)

    def clear() -> tk.Frame:
        for child in outer.winfo_children():
            child.destroy()
        tk.Label(outer, text="ACCESS  /  LAB", fg=C["accent"], bg=C["bg"],
                 font=("Arial", 12, "bold")).pack(anchor="w")
        tk.Label(outer, text="Authentication System", fg=C["white"], bg=C["bg"],
                 font=("Arial", 29, "bold")).pack(anchor="w", pady=(4, 0))
        tk.Label(outer, text="A real local implementation of your Python homework.",
                 fg=C["muted"], bg=C["bg"], font=("Arial", 11)).pack(anchor="w", pady=(2, 22))
        card = tk.Frame(outer, bg=C["panel"], highlightthickness=1,
                        highlightbackground=C["line"], padx=33, pady=25)
        card.pack(fill="both", expand=True)
        return card

    def heading(card: tk.Frame, title: str, subtitle: str) -> None:
        tk.Label(card, text=title, fg=C["white"], bg=C["panel"],
                 font=("Arial", 19, "bold")).pack(anchor="w")
        tk.Label(card, text=subtitle, fg=C["muted"], bg=C["panel"],
                 wraplength=690, justify="left").pack(anchor="w", pady=(3, 17))

    def field(card: tk.Frame, title: str, secret: bool = False) -> tk.Entry:
        tk.Label(card, text=title, fg=C["muted"], bg=C["panel"],
                 font=("Arial", 10, "bold")).pack(anchor="w", pady=(8, 3))
        entry = tk.Entry(card, bg=C["field"], fg=C["white"],
                         insertbackground=C["white"], relief="flat", bd=0,
                         font=("Arial", 13), show="•" if secret else "")
        entry.pack(fill="x", ipady=9)
        if secret:
            visible = tk.BooleanVar(value=False)
            tk.Checkbutton(card, text="Show password", variable=visible,
                           command=lambda: entry.config(show="" if visible.get() else "•"),
                           fg=C["muted"], bg=C["panel"], activebackground=C["panel"],
                           activeforeground=C["white"], selectcolor=C["field"],
                           relief="flat", bd=0).pack(anchor="w")
        return entry

    def button(card: tk.Frame, label: str, command: object, primary: bool = True) -> None:
        bg = C["accent"] if primary else C["field"]
        fg = C["bg"] if primary else C["white"]
        tk.Button(card, text=label, command=command, bg=bg, fg=fg,
                  activebackground="#8aefd4" if primary else C["line"],
                  activeforeground=C["bg"] if primary else C["white"],
                  relief="flat", bd=0, padx=16, pady=9, cursor="hand2",
                  font=("Arial", 11, "bold")).pack(fill="x", pady=(10, 0))

    def status(card: tk.Frame) -> tk.Label:
        label = tk.Label(card, text="", bg=C["panel"], fg=C["red"],
                         wraplength=690, anchor="w", justify="left")
        label.pack(fill="x", pady=(10, 0))
        return label

    def recovery_code_screen(code: str, message: str) -> None:
        card = clear()
        heading(card, "Save your recovery code", message)
        tk.Label(card, text="This is displayed only once. Keep it private.",
                 bg=C["panel"], fg=C["gold"]).pack(anchor="w", pady=(3, 12))
        secret_code = tk.Entry(card, bg=C["field"], fg=C["accent"],
                               insertbackground=C["accent"], relief="flat",
                               font=("Consolas", 14), readonlybackground=C["field"])
        secret_code.insert(0, code)
        secret_code.config(state="readonly")
        secret_code.pack(fill="x", ipady=12)
        def copy_code() -> None:
            root.clipboard_clear()
            root.clipboard_append(code)
            messagebox.showinfo("Copied", "Recovery code copied. Do not share it.")
        button(card, "Copy recovery code", copy_code)
        button(card, "I saved it — continue to login", login_screen, False)

    def login_screen() -> None:
        nonlocal active_user
        active_user = None
        card = clear()
        heading(card, "Welcome back", "Enter your User ID and password to verify your identity.")
        username = field(card, "USER ID")
        password = field(card, "PASSWORD", True)
        outcome = status(card)
        def submit(_event: object = None) -> None:
            nonlocal active_user
            try:
                result = store.login(username.get().strip(), password.get())
                password.delete(0, "end")
                if result.success:
                    active_user = result.username
                    messagebox.showinfo("Access granted", "Grant Access")
                    dashboard()
                else:
                    outcome.config(text="Wrong Credentials", fg=C["red"])
            except Exception as exc:
                outcome.config(text=f"Unable to authenticate: {exc}", fg=C["red"])
        password.bind("<Return>", submit)
        button(card, "Login  →", submit)
        button(card, "Create a new account", register_screen, False)
        button(card, "Use a recovery code", recover_screen, False)
        username.focus_set()

    def register_screen() -> None:
        card = clear()
        heading(card, "Create an account", "No default credentials. Register your own account and keep its recovery code.")
        username = field(card, "CHOOSE USER ID")
        password = field(card, "PASSWORD (12+ CHARACTERS)", True)
        confirm = field(card, "CONFIRM PASSWORD", True)
        outcome = status(card)
        def submit() -> None:
            try:
                if password.get() != confirm.get():
                    raise AuthError("Passwords do not match.")
                code = store.register(username.get().strip(), password.get())
                recovery_code_screen(code, "Account created successfully.")
            except (AuthError, sqlite3.Error) as exc:
                outcome.config(text=str(exc))
        button(card, "Register account", submit)
        button(card, "← Back to login", login_screen, False)
        username.focus_set()

    def recover_screen() -> None:
        card = clear()
        heading(card, "Recover your account", "Use the private recovery code issued at registration. This rotates the code.")
        username = field(card, "USER ID")
        code = field(card, "RECOVERY CODE", True)
        new_pass = field(card, "NEW PASSWORD", True)
        confirm = field(card, "CONFIRM NEW PASSWORD", True)
        outcome = status(card)
        def submit() -> None:
            try:
                if new_pass.get() != confirm.get():
                    raise AuthError("Passwords do not match.")
                replacement = store.recover(username.get().strip(), code.get(), new_pass.get())
                recovery_code_screen(replacement, "Password reset. Your old recovery code is now invalid.")
            except (AuthError, sqlite3.Error) as exc:
                outcome.config(text=str(exc))
        button(card, "Reset password", submit)
        button(card, "← Back to login", login_screen, False)
        username.focus_set()

    def change_screen() -> None:
        if not active_user:
            login_screen()
            return
        card = clear()
        heading(card, "Change password", f"Authenticated user: {active_user}")
        old_pass = field(card, "CURRENT PASSWORD", True)
        new_pass = field(card, "NEW PASSWORD", True)
        confirm = field(card, "CONFIRM NEW PASSWORD", True)
        outcome = status(card)
        def submit() -> None:
            try:
                if new_pass.get() != confirm.get():
                    raise AuthError("Passwords do not match.")
                store.change_password(active_user, old_pass.get(), new_pass.get())
                messagebox.showinfo("Updated", "Password changed successfully.")
                dashboard()
            except (AuthError, sqlite3.Error) as exc:
                outcome.config(text=str(exc))
        button(card, "Save new password", submit)
        button(card, "← Back to dashboard", dashboard, False)

    def dashboard() -> None:
        if not active_user:
            login_screen()
            return
        card = clear()
        heading(card, "Grant Access", f"Welcome, {active_user}. Your credentials were verified successfully.")
        info = store.profile(active_user)
        for title, value in (("USER ID", info["username"]), ("ACCOUNT CREATED", info["created"]),
                             ("LAST LOGIN (UTC)", info["last_login"] or "Not available")):
            tk.Label(card, text=f"{title}     {value}", fg=C["white"], bg=C["panel"],
                     font=("Arial", 11)).pack(anchor="w", pady=(2, 5))
        tk.Label(card, text="RECENT SECURITY ACTIVITY", fg=C["accent"], bg=C["panel"],
                 font=("Arial", 10, "bold")).pack(anchor="w", pady=(17, 5))
        for action, when in store.activity(active_user, 5):
            tk.Label(card, text=f"{when}   /   {action}", fg=C["muted"],
                     bg=C["panel"], font=("Consolas", 9)).pack(anchor="w")
        button(card, "Change password", change_screen)
        button(card, "Log out", login_screen, False)

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
