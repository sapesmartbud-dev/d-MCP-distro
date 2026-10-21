# SAPÉ d-MCP — controlled database access with granular permissions for LLMs
# Copyright (C) 2026 Luciano Arrezze
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-only

"""Connection passwords: the OS keyring where there is one, an AES-GCM vault where there is not."""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import secrets
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# The keyring service name and the account shape, from DESIGN-DATA-MODEL.md §3.5.
# The account is derived from the primary key rather than the display name, so
# renaming a connection does not orphan its password — and because ids are never
# recycled (§3.2), an orphaned account can never be handed to a different
# connection.
SERVICE_NAME = "SAPE-d-MCP"
_ACCOUNT_PREFIX = "conn:"

# Written and read by the probe in _keyring_usable().  A random value, never a
# real secret, and deleted again in the same call.
_PROBE_ACCOUNT = "__dmcp_backend_probe__"

VAULT_FILENAME = "credentials.vault"
VAULT_FORMAT_VERSION = 1

# Environment variable that unlocks the AES vault without a prompt, for a
# headless MCP server started by a client such as Claude Desktop, where there is
# no window to type a master password into and no keyring daemon either.
# Deliberately opt-in and logged at WARNING every time it is used: putting a
# master password in the process environment is weaker than typing it, and the
# operator should be making that trade knowingly.  It is never read into a log
# line, an exception or a repr.
MASTER_PASSWORD_ENV = "DMCP_MASTER_PASSWORD"

# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
# The vault key is derived from a master password, so the KDF is the only thing
# standing between a stolen ~/.sape/d-mcp/credentials.vault and every database
# password in it.  A fast hash would let an attacker try billions of candidate
# passwords per second on a GPU; a memory-hard one makes each attempt cost RAM,
# which is what GPUs and ASICs are short of.
#
# First choice is Argon2id at RFC 9106's second recommended profile —
# m = 64 MiB, t = 3, p = 4 — the PHC winner and the current mainstream
# recommendation, and the one that resists both GPU and side-channel attack.
# cryptography exposes it only from 44.0 and only against OpenSSL 3.2+, and this
# project's declared floor is cryptography>=42.0, so where it is unavailable the
# vault falls back to scrypt (RFC 7914) at N = 2^16, r = 8, p = 1 — the same
# 64 MiB memory cost, available in every supported build.
#
# Measured on the development machine: Argon2id 0.12 s, scrypt 0.30 s.  Both are
# comfortably below the threshold at which a once-per-session unlock becomes
# annoying, and both are far above what a brute-force campaign can afford.
#
# The vault header records which was used and with what parameters, so a file
# written by either build opens under the same code and the parameters can be
# raised later without stranding existing vaults.
_ARGON2_PARAMS: dict[str, int] = {"memory_cost": 65536, "iterations": 3, "lanes": 4}
_SCRYPT_PARAMS: dict[str, int] = {"n": 65536, "r": 8, "p": 1}

_SALT_BYTES = 16
_KEY_BYTES = 32  # AES-256
_NONCE_BYTES = 12  # AES-GCM standard nonce length

# Plaintext of the verifier blob.  Decrypting it proves the master password was
# right, so unlock() can answer False instead of failing later with a confusing
# "password not found" when the real problem was a typo at the prompt.
_VERIFIER_PLAINTEXT = b"SAPE d-MCP credential vault"
_VERIFIER_AAD = b"dmcp-vault-verifier"


class CredentialError(RuntimeError):
    """A credential could not be stored or retrieved.  Never carries the secret."""


class VaultLocked(CredentialError):
    """The AES vault is in use and no master password has been supplied yet."""


def account_for(connection_id: int) -> str:
    """The keyring/vault account name for a connection id."""
    return f"{_ACCOUNT_PREFIX}{int(connection_id)}"


def config_dir() -> Path:
    """``~/.sape/d-mcp/`` — the namespaced directory, overridable for tests.

    The ``d-mcp/`` segment is not cosmetic: f-MCP writes straight into
    ``~/.sape/``, and without it the two applications clobber each other.
    """
    override = os.environ.get("DMCP_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".sape" / "d-mcp"


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------
# Cached per process.  The probe costs a keyring round trip and the answer cannot
# change while the process runs without something far more alarming happening.
_probe_cache: dict[str, tuple[bool, str]] = {}


def reset_backend_probe() -> None:
    """Forget the cached probe result.  For tests only."""
    _probe_cache.clear()


def _keyring_usable(service: str) -> tuple[bool, str]:
    """Decide whether the OS keyring actually works, by using it.

    Inspecting ``keyring.get_keyring()`` is not enough, and this is the bug the
    method exists for: on a headless Linux box ``keyring`` happily reports
    ``keyring.backends.SecretService.Keyring`` because the *Python* package is
    installed, and the call then fails at runtime with a D-Bus error because
    there is no session bus and no ``gnome-keyring-daemon``.  A name check would
    hand us a backend that cannot store anything; a real set/get/delete round
    trip is the only honest test.  The probe writes a random token under a
    reserved account name and removes it again — never a real password.
    """
    cached = _probe_cache.get(service)
    if cached is not None:
        return cached

    verdict: tuple[bool, str]
    try:
        import keyring
        from keyring.backends import fail as keyring_fail
    except Exception as exc:  # pragma: no cover - keyring is a hard requirement
        verdict = (False, f"keyring is not importable ({type(exc).__name__})")
        _probe_cache[service] = verdict
        return verdict

    try:
        backend = keyring.get_keyring()
    except Exception as exc:
        verdict = (False, f"keyring could not select a backend ({type(exc).__name__})")
        _probe_cache[service] = verdict
        return verdict

    # Built from the *type*, never from str(backend): keyring's __str__ renders
    # the backend's `priority`, and SecretService computes that by opening a
    # D-Bus connection — so on a headless box merely printing the backend raises
    # FileNotFoundError.  Verified live: with DBUS_SESSION_BUS_ADDRESS pointing
    # at a socket that is not there, str(keyring.get_keyring()) blows up while
    # type(...).__qualname__ is perfectly safe.
    name = f"{type(backend).__module__}.{type(backend).__qualname__}"

    if isinstance(backend, keyring_fail.Keyring):
        _probe_cache[service] = (False, "no OS credential store is available")
        return _probe_cache[service]

    token = secrets.token_urlsafe(16)
    try:
        keyring.set_password(service, _PROBE_ACCOUNT, token)
        echoed = keyring.get_password(service, _PROBE_ACCOUNT)
    except Exception as exc:
        # The interesting failure: the backend exists as a class but not as a
        # running service.  Log the type only — a keyring error can quote the
        # value it was asked to store.
        logger.info(
            "OS keyring backend %s is present but unusable (%s); falling back to the "
            "encrypted vault.",
            name,
            type(exc).__name__,
        )
        _probe_cache[service] = (False, f"{name} is present but not working")
        return _probe_cache[service]
    finally:
        try:
            import keyring as _kr

            _kr.delete_password(service, _PROBE_ACCOUNT)
        except Exception:
            logger.debug("Could not remove the keyring probe entry", exc_info=True)

    if echoed != token:
        # A backend that accepts a write and returns something else is worse than
        # one that fails: it would silently lose every password.
        logger.warning(
            "OS keyring backend %s did not return what it was asked to store; "
            "falling back to the encrypted vault.",
            name,
        )
        _probe_cache[service] = (False, f"{name} did not round-trip a value")
        return _probe_cache[service]

    _probe_cache[service] = (True, name)
    return _probe_cache[service]


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class CredentialStore:
    """Stores one password per connection, outside every ``.db`` file.

    Primary backend is the OS keyring — Windows Credential Manager, macOS
    Keychain, Secret Service on Linux.  Where a real round trip proves there is
    no working backend, an AES-256-GCM vault under ``~/.sape/d-mcp/`` takes over,
    keyed from a master password.

    Nothing here logs a password, puts one in an exception message, or lets one
    reach ``repr()``: the secret exists only as a local name inside the method
    that is storing or fetching it.
    """

    def __init__(
        self,
        service: str = SERVICE_NAME,
        vault_path: str | os.PathLike[str] | None = None,
        backend: str = "auto",
    ) -> None:
        if backend not in ("auto", "keyring", "vault"):
            raise ValueError(f"backend must be 'auto', 'keyring' or 'vault', got {backend!r}")
        self.service = service
        self._vault_path = (
            Path(vault_path).expanduser() if vault_path is not None else config_dir() / VAULT_FILENAME
        )
        self._key: bytes | None = None

        if backend == "keyring":
            usable, name = _keyring_usable(service)
            if not usable:
                raise CredentialError(
                    f"The OS credential store cannot be used: {name}. "
                    "Choose the encrypted vault instead."
                )
            self._use_keyring = True
            self._backend_detail = name
        elif backend == "vault":
            self._use_keyring = False
            self._backend_detail = "forced"
        else:
            self._use_keyring, self._backend_detail = _keyring_usable(service)

        if not self._use_keyring:
            logger.info(
                "Using the encrypted credential vault at %s (%s).",
                self._vault_path,
                self._backend_detail,
            )

    def __repr__(self) -> str:
        # Explicit, so no future attribute can leak into a traceback frame dump.
        state = "unlocked" if not self.is_locked() else "locked"
        return f"<CredentialStore backend={self.backend_name()!r} {state}>"

    # -- introspection ---------------------------------------------------

    def backend_name(self) -> str:
        """A short description for the Settings page.  Never a path to a secret's value."""
        if self._use_keyring:
            return f"OS keyring ({self._backend_detail})"
        return f"Encrypted vault ({self._vault_path})"

    def uses_keyring(self) -> bool:
        """``True`` when the OS credential store is in use."""
        return self._use_keyring

    @property
    def vault_path(self) -> Path:
        """Where the AES vault lives, whether or not it is in use."""
        return self._vault_path

    def vault_exists(self) -> bool:
        """``True`` when a vault file is already on disk.

        The GUI uses it to decide between "enter your master password" and
        "choose a master password".
        """
        return self._vault_path.is_file()

    def is_locked(self) -> bool:
        """``True`` only when the vault is the backend and no key has been derived."""
        if self._use_keyring:
            return False
        if self._key is not None:
            return False
        return not self._try_environment_unlock()

    # -- unlocking -------------------------------------------------------

    def unlock(self, master_password: str) -> bool:
        """Derive the vault key from ``master_password``.  AES fallback only.

        Returns ``True`` on success and ``False`` for a wrong password; it does
        not raise for a wrong password, because the caller is a dialog that wants
        to say "try again", not a traceback.  Creates the vault on first use.
        """
        if self._use_keyring:
            # Not an error: the GUI calls unlock() unconditionally at start-up
            # and should not have to know which backend was selected.
            return True
        if not master_password:
            return False

        if not self._vault_path.is_file():
            self._create_vault(master_password)
            logger.info("Created a new encrypted credential vault at %s", self._vault_path)
            return True

        vault = self._read_vault()
        key = self._derive_key(master_password, vault)
        if not self._verify(key, vault):
            logger.warning("The master password did not open the credential vault.")
            return False
        self._key = key
        return True

    def lock(self) -> None:
        """Drop the derived key.  Cheap insurance before a long idle period."""
        self._key = None

    def _try_environment_unlock(self) -> bool:
        """Unlock from ``DMCP_MASTER_PASSWORD`` if it is set.  See the constant's note."""
        master = os.environ.get(MASTER_PASSWORD_ENV)
        if not master:
            return False
        logger.warning(
            "Unlocking the credential vault from %s. A master password in the process "
            "environment is visible to anything that can read this process's environment; "
            "prefer the GUI prompt where there is one.",
            MASTER_PASSWORD_ENV,
        )
        return self.unlock(master)

    def _require_key(self) -> bytes:
        if self._key is None and not self._try_environment_unlock():
            raise VaultLocked(
                "The encrypted credential vault is locked. Enter the master password "
                f"in Settings, or set {MASTER_PASSWORD_ENV} before starting a headless "
                "server."
            )
        assert self._key is not None  # narrowed by the unlock above
        return self._key

    # -- the API the GUI and engine.py use -------------------------------

    def set_password(self, connection_id: int, password: str) -> None:
        """Store the password for a connection.  Overwrites any previous value.

        **Only a profile whose ``auth_mode`` is ``'password'`` may have an entry here.**
        This store deliberately never opens ``connections.db`` — it holds secrets and
        nothing else — so it cannot check that for itself, and the rule is enforced where
        the mode is known: ``ConnectionStore.update()`` deletes the entry when a profile
        stops authenticating with a password, and ``engine.connect()`` refuses to be handed
        one for a profile that does not.  A stale entry that survived a failed purge is
        therefore inert rather than dangerous — the mode decides, never the presence of a
        secret — but it is still a credential nothing can address, and it should not be
        created in the first place.
        """
        if password is None:
            raise ValueError("password must be a string; use delete_password() to remove one.")
        account = account_for(connection_id)
        if self._use_keyring:
            try:
                import keyring

                keyring.set_password(self.service, account, password)
            except Exception as exc:
                # str(exc) is deliberately not interpolated: several backends
                # echo the value they were handed into the error text.
                raise CredentialError(
                    f"The OS credential store refused to save the password for "
                    f"connection {connection_id} ({type(exc).__name__}). "
                    "Check that the credential service is running."
                ) from None
        else:
            key = self._require_key()
            vault = self._read_vault()
            vault["entries"][account] = _b64(_encrypt(key, password.encode("utf-8"), account))
            self._write_vault(vault)
        logger.info("Stored a password for connection %s", connection_id)

    def get_password(self, connection_id: int) -> str | None:
        """The stored password, or ``None`` when there is none."""
        account = account_for(connection_id)
        if self._use_keyring:
            try:
                import keyring

                return keyring.get_password(self.service, account)
            except Exception as exc:
                raise CredentialError(
                    f"The OS credential store could not be read for connection "
                    f"{connection_id} ({type(exc).__name__}). "
                    "Check that the credential service is running."
                ) from None

        key = self._require_key()
        vault = self._read_vault()
        blob = vault["entries"].get(account)
        if blob is None:
            return None
        try:
            return _decrypt(key, _unb64(blob), account).decode("utf-8")
        except Exception:
            # Wrong key, or a tampered file.  Neither is recoverable here and
            # neither may leak anything about the plaintext.
            raise CredentialError(
                f"The stored password for connection {connection_id} could not be "
                "decrypted. The vault may have been written with a different master "
                "password, or altered."
            ) from None

    def delete_password(self, connection_id: int) -> None:
        """Remove the stored password.  A missing entry is not an error.

        Called first in ``ConnectionStore.delete()``'s cascade
        (DESIGN-DATA-MODEL.md §7.2), before the row that names the account is
        destroyed.
        """
        account = account_for(connection_id)
        if self._use_keyring:
            try:
                import keyring
                from keyring.errors import PasswordDeleteError

                try:
                    keyring.delete_password(self.service, account)
                except PasswordDeleteError:
                    logger.debug("No keyring entry to delete for connection %s", connection_id)
                    return
            except Exception as exc:
                raise CredentialError(
                    f"The OS credential store could not delete the password for "
                    f"connection {connection_id} ({type(exc).__name__})."
                ) from None
        else:
            # Called for its side effect: refuse to rewrite the vault unless it
            # is open, so a locked session cannot blank an entry it cannot read.
            self._require_key()
            vault = self._read_vault()
            if vault["entries"].pop(account, None) is None:
                return
            self._write_vault(vault)
        logger.info("Deleted the stored password for connection %s", connection_id)

    def has_password(self, connection_id: int) -> bool:
        """Whether a password is stored, without producing it."""
        if self._use_keyring:
            return self.get_password(connection_id) is not None
        vault = self._read_vault() if self._vault_path.is_file() else {"entries": {}}
        return account_for(connection_id) in vault.get("entries", {})

    # -- the vault file --------------------------------------------------

    def _create_vault(self, master_password: str) -> None:
        salt = secrets.token_bytes(_SALT_BYTES)
        kdf_name, params = _preferred_kdf()
        vault: dict[str, Any] = {
            "version": VAULT_FORMAT_VERSION,
            "kdf": kdf_name,
            "kdf_params": params,
            "salt": _b64(salt),
            "entries": {},
        }
        key = self._derive_key(master_password, vault)
        vault["verifier"] = _b64(_encrypt(key, _VERIFIER_PLAINTEXT, _VERIFIER_AAD.decode()))
        self._key = key
        self._write_vault(vault)

    @staticmethod
    def _derive_key(master_password: str, vault: dict[str, Any]) -> bytes:
        salt = _unb64(vault["salt"])
        kdf_name = str(vault.get("kdf", "scrypt"))
        params = dict(vault.get("kdf_params") or {})
        derive = _KDFS.get(kdf_name)
        if derive is None:
            raise CredentialError(
                f"The credential vault was written with an unknown key-derivation "
                f"function ({kdf_name!r}). It needs a newer build of SAPÉ d-MCP."
            )
        return derive(master_password.encode("utf-8"), salt, params)

    @staticmethod
    def _verify(key: bytes, vault: dict[str, Any]) -> bool:
        blob = vault.get("verifier")
        if not blob:
            # A vault with no verifier predates this format; treat any successful
            # entry decryption as the check instead of refusing to open it.
            return True
        try:
            return _decrypt(key, _unb64(blob), _VERIFIER_AAD.decode()) == _VERIFIER_PLAINTEXT
        except Exception:
            return False

    def _read_vault(self) -> dict[str, Any]:
        if not self._vault_path.is_file():
            raise CredentialError(
                f"There is no credential vault at {self._vault_path}. "
                "Set a master password in Settings to create one."
            )
        try:
            data = json.loads(self._vault_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CredentialError(
                f"The credential vault at {self._vault_path} could not be read: {exc}"
            ) from None
        if not isinstance(data, dict) or "entries" not in data:
            raise CredentialError(
                f"The credential vault at {self._vault_path} is not in the expected format."
            )
        if int(data.get("version", 0)) > VAULT_FORMAT_VERSION:
            raise CredentialError(
                f"The credential vault at {self._vault_path} was written by a newer "
                "version of SAPÉ d-MCP. Upgrade rather than letting this build "
                "misread it."
            )
        data.setdefault("entries", {})
        return data

    def _write_vault(self, vault: dict[str, Any]) -> None:
        """Write atomically, owner-only.

        A partial write here loses every password at once, so the file is
        replaced rather than truncated: the temporary file is created in the same
        directory (so ``os.replace`` is atomic) and with mode 0600 from the
        outset, not chmod-ed afterwards, which would leave a window where it is
        world-readable.
        """
        directory = self._vault_path.parent
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            # Windows and some network filesystems do not implement POSIX modes.
            logger.debug("Could not restrict permissions on %s", directory, exc_info=True)

        payload = json.dumps(vault, indent=2, sort_keys=True)
        fd, tmp_name = tempfile.mkstemp(dir=str(directory), prefix=".vault-", suffix=".tmp")
        try:
            os.chmod(tmp_name, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self._vault_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise
        try:
            os.chmod(self._vault_path, 0o600)
        except OSError:
            logger.debug("Could not restrict permissions on %s", self._vault_path, exc_info=True)


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _encrypt(key: bytes, plaintext: bytes, aad: str) -> bytes:
    """AES-256-GCM.  The nonce is prepended; the account name is authenticated data.

    Binding the ciphertext to the account name is not decoration: without it an
    attacker with write access to the vault could copy the production
    connection's blob over the development connection's, then read the
    production password back through a profile they are allowed to test.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(_NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad.encode("utf-8"))


def _decrypt(key: bytes, blob: bytes, aad: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad.encode("utf-8"))


def _derive_argon2id(password: bytes, salt: bytes, params: dict[str, int]) -> bytes:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    return Argon2id(
        salt=salt,
        length=_KEY_BYTES,
        iterations=int(params.get("iterations", _ARGON2_PARAMS["iterations"])),
        lanes=int(params.get("lanes", _ARGON2_PARAMS["lanes"])),
        memory_cost=int(params.get("memory_cost", _ARGON2_PARAMS["memory_cost"])),
    ).derive(password)


def _derive_scrypt(password: bytes, salt: bytes, params: dict[str, int]) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Scrypt(
        salt=salt,
        length=_KEY_BYTES,
        n=int(params.get("n", _SCRYPT_PARAMS["n"])),
        r=int(params.get("r", _SCRYPT_PARAMS["r"])),
        p=int(params.get("p", _SCRYPT_PARAMS["p"])),
    ).derive(password)


_KDFS: dict[str, Callable[[bytes, bytes, dict[str, int]], bytes]] = {
    "argon2id": _derive_argon2id,
    "scrypt": _derive_scrypt,
}


def _argon2id_available() -> bool:
    """Whether this build of ``cryptography`` can do Argon2id at all.

    Importable is not sufficient — the class exists from 44.0 but raises
    ``UnsupportedAlgorithm`` when linked against OpenSSL below 3.2 — so the check
    is a one-off derivation with a throwaway salt.
    """
    try:
        _derive_argon2id(b"probe", b"0" * _SALT_BYTES, {"memory_cost": 8, "iterations": 1, "lanes": 1})
    except Exception:
        return False
    return True


def _preferred_kdf() -> tuple[str, dict[str, int]]:
    """The KDF a *new* vault is created with.  Existing vaults keep their own."""
    if _argon2id_available():
        return "argon2id", dict(_ARGON2_PARAMS)
    logger.info(
        "Argon2id is unavailable in this build of cryptography; the credential vault "
        "will use scrypt at the same 64 MiB memory cost."
    )
    return "scrypt", dict(_SCRYPT_PARAMS)
