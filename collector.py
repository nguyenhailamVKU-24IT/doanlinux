"""Read-only Ubuntu security data collector.

All subprocess calls use argv lists and a fixed command registry. The collector
never accepts a command from an HTTP request and never uses shell=True.
"""
from __future__ import annotations

import os
import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = PROJECT_ROOT / "evidence" / "security_reports"
LOG_DIR = PROJECT_ROOT / "evidence" / "logs"
TEST_CASES_FILE = PROJECT_ROOT / "tests" / "test_cases.csv"
LAB_FILE = Path("/srv/security-lab/secret.txt")

Command = tuple[str, ...]


@dataclass(frozen=True)
class CommandResult:
    command: Command
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class SafeCommandRunner:
    """Execute only commands declared in the fixed read-only registry."""

    def __init__(self, executor: Callable[..., subprocess.CompletedProcess] | None = None):
        self._executor = executor or subprocess.run
        self.privileged_keys = frozenset({
            "ssh_service",
            "ssh_enabled",
            "ssh_config",
            "ssh_validate",
            "ufw_status",
            "fail2ban_service",
            "fail2ban_status",
            "fail2ban_sshd",
            "testuser_read",
        })
        self.registry: dict[str, Command] = {
            "hostname": ("/usr/bin/hostname",),
            "ip_addresses": ("/usr/bin/hostname", "-I"),
            "os_release": ("/usr/bin/cat", "/etc/os-release"),
            "architecture": ("/usr/bin/uname", "-m"),
            "kernel": ("/usr/bin/uname", "-sr"),
            "memory": ("/usr/bin/free", "-h"),
            "disk": ("/usr/bin/df", "-h", "/"),
            "ssh_service": ("/usr/bin/systemctl", "is-active", "ssh"),
            "ssh_enabled": ("/usr/bin/systemctl", "is-enabled", "ssh"),
            "ssh_config": ("/usr/sbin/sshd", "-T"),
            "ssh_validate": ("/usr/sbin/sshd", "-t"),
            "ufw_status": ("/usr/sbin/ufw", "status", "verbose"),
            "fail2ban_service": ("/usr/bin/systemctl", "is-active", "fail2ban"),
            "fail2ban_status": ("/usr/bin/fail2ban-client", "status"),
            "fail2ban_sshd": ("/usr/bin/fail2ban-client", "status", "sshd"),
            "permissions": ("/usr/bin/stat", "-c", "%A %a %U:%G %n", str(LAB_FILE)),
            "owner_read": ("/usr/bin/test", "-r", str(LAB_FILE)),
            "testuser_read": ("/usr/sbin/runuser", "-u", "testuser", "--", "/usr/bin/test", "-r", str(LAB_FILE)),
            "upgradable": ("/usr/bin/apt", "list", "--upgradable"),
        }

    def run(self, key: str, timeout: int = 8) -> CommandResult:
        command = self.registry[key]
        result = self._execute(command, timeout)
        if key in self.privileged_keys and self._looks_privileged(result):
            # Keep Flask unprivileged while allowing a user's cached sudo
            # credential to run only this fixed, read-only check.
            elevated = ("/usr/bin/sudo", "-n", "--", *command)
            elevated_result = self._execute(elevated, timeout)
            if elevated_result.returncode != 127:
                return elevated_result
        return result

    def _execute(self, command: Command, timeout: int) -> CommandResult:
        try:
            completed = self._executor(
                list(command),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
            return CommandResult(command, completed.returncode, completed.stdout or "", completed.stderr or "")
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return CommandResult(command, 127, "", str(exc))
        except subprocess.TimeoutExpired as exc:
            return CommandResult(command, 124, exc.stdout or "", exc.stderr or "", timed_out=True)

    @staticmethod
    def _looks_privileged(result: CommandResult) -> bool:
        text = result.stderr.lower()
        markers = ("permission denied", "you need to be root", "may not be used", "operation not permitted", "failed to connect to bus", "permission denied to socket")
        return any(marker in text for marker in markers)

    def command_for(self, key: str) -> Command:
        return self.registry[key]

    def run_audit(self, timeout: int = 30) -> CommandResult:
        """Run only the project's known read-only audit script."""
        command: Command = (
            "/usr/bin/bash",
            str(PROJECT_ROOT / "scripts" / "security_audit.sh"),
            str(REPORT_DIR),
        )
        try:
            completed = self._executor(
                list(command),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
            return CommandResult(command, completed.returncode, completed.stdout or "", completed.stderr or "")
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return CommandResult(command, 127, "", str(exc))
        except subprocess.TimeoutExpired as exc:
            return CommandResult(command, 124, exc.stdout or "", exc.stderr or "", timed_out=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def first_line(value: str) -> str:
    return next((line.strip() for line in value.splitlines() if line.strip()), "")


def parse_os_release(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"')
    return result


def status(value: str | None, *, expected: Iterable[str] = ("active", "enabled", "yes", "running")) -> str:
    if value is None:
        return "UNKNOWN"
    return "PASS" if value.strip().lower() in set(expected) else "FAIL"


def result_value(result: CommandResult) -> str | None:
    if result.returncode == 127 and not result.stdout:
        return None
    return first_line(result.stdout)


def redact_ips(raw: str) -> list[str]:
    values: list[str] = []
    for token in raw.split():
        if "." in token:
            parts = token.split(".")
            values.append(".".join(parts[:3] + ["x"]) if len(parts) == 4 else "redacted")
        elif ":" in token:
            parts = token.split(":")
            values.append(":".join(parts[:3] + ["xxxx"]))
    return values


def parse_ssh_config(raw: str) -> dict[str, str]:
    wanted = {"port", "maxauthtries", "permitrootlogin", "pubkeyauthentication", "passwordauthentication"}
    values: dict[str, str] = {}
    for line in raw.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in wanted:
            values[parts[0].lower()] = parts[1].strip()
    return values


def parse_ufw(raw: str) -> dict:
    lower = raw.lower()
    rules = []
    for line in raw.splitlines():
        if re.match(r"^\d+(/\w+)?", line.strip()):
            rules.append(" ".join(line.split()))
    active = "status: active" in lower
    incoming = bool(re.search(r"default:\s*deny\s*\(incoming\)", lower))
    outgoing = bool(re.search(r"(?:default:[^\n]*,\s*)?allow\s*\(outgoing\)", lower))
    return {
        "active": active,
        "default_incoming": "deny" if incoming else ("allow" if "default: allow (incoming)" in lower else None),
        "default_outgoing": "allow" if outgoing else ("deny" if "default: deny (outgoing)" in lower else None),
        "rules": rules,
        "status": "PASS" if active and incoming and outgoing else ("UNKNOWN" if not raw else "FAIL"),
    }


def parse_fail2ban(raw: str, jail_raw: str) -> dict:
    def field(text: str, label: str) -> int | None:
        match = re.search(rf"{re.escape(label)}:\s*(\d+)", text)
        return int(match.group(1)) if match else None

    jail_match = re.search(r"Jail list:\s*(.*)", raw)
    jail = jail_match.group(1).strip() if jail_match else None
    banned = field(jail_raw, "Currently banned")
    failed = field(jail_raw, "Currently failed")
    return {
        "jail": jail,
        "currently_failed": failed,
        "currently_banned": banned,
        "total_banned": field(jail_raw, "Total banned"),
        "status": "PASS" if jail and "sshd" in jail else ("UNKNOWN" if not raw else "FAIL"),
        "ban_test_status": "UNKNOWN" if banned in (None, 0) else "PASS",
    }


def parse_permissions(result: CommandResult, owner: CommandResult, testuser: CommandResult) -> dict:
    raw = first_line(result.stdout)
    mode_match = re.search(r"\b([0-7]{3,4})\b", raw)
    mode = mode_match.group(1)[-3:] if mode_match else None
    owner_readable = owner.ok if owner.returncode != 127 else None
    # A non-root dashboard cannot impersonate testuser with runuser. Do not
    # turn that tool limitation into a false permission denial.
    if testuser.returncode == 0:
        testuser_readable = True
    elif testuser.returncode == 1 and not testuser.stderr.strip():
        # `test -r` returns 1 with no output when the target user cannot read.
        testuser_readable = False
    else:
        testuser_readable = None
    return {
        "path": str(LAB_FILE),
        "raw": raw or None,
        "mode": mode,
        "owner_readable": owner_readable if result.returncode != 127 else None,
        "testuser_readable": testuser_readable if result.returncode != 127 else None,
        "status": "PASS" if mode == "600" and owner_readable is True and testuser_readable is False else ("UNKNOWN" if not raw or testuser_readable is None else "FAIL"),
    }


def parse_updates(raw: str, returncode: int) -> dict:
    packages = []
    for line in raw.splitlines():
        if "/" in line and "[upgradable from:" in line:
            packages.append(line.strip())
    return {"count": len(packages) if returncode != 127 else None, "packages": packages[:100], "status": "PASS" if returncode == 0 else "UNKNOWN"}

def permission_warning(results: dict[str, CommandResult], keys: Iterable[str]) -> str | None:
    messages = []
    for key in keys:
        result = results[key]
        if not result.ok and result.stderr.strip():
            messages.append(result.stderr.strip().splitlines()[-1])
    return " Một số kiểm tra cần quyền quản trị: " + " | ".join(messages[:2]) if messages else None


def read_json_file(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def collect_snapshot(runner: SafeCommandRunner | None = None) -> dict:
    runner = runner or SafeCommandRunner()
    results = {key: runner.run(key) for key in runner.registry}
    os_info = parse_os_release(results["os_release"].stdout)
    hostname = result_value(results["hostname"])
    ssh = parse_ssh_config(results["ssh_config"].stdout)
    ufw = parse_ufw(results["ufw_status"].stdout)
    fail2ban = parse_fail2ban(results["fail2ban_status"].stdout, results["fail2ban_sshd"].stdout)
    permissions = parse_permissions(results["permissions"], results["owner_read"], results["testuser_read"])
    updates = parse_updates(results["upgradable"].stdout, results["upgradable"].returncode)

    service_ssh = result_value(results["ssh_service"])
    enabled_ssh = result_value(results["ssh_enabled"])
    service_f2b = result_value(results["fail2ban_service"])
    ssh_required = {
        "permitrootlogin": "no",
        "pubkeyauthentication": "yes",
        "passwordauthentication": "no",
        "maxauthtries": "3",
    }
    ssh_values_available = all(key in ssh for key in ssh_required)
    ssh_status = (
        "PASS"
        if service_ssh == "active" and enabled_ssh == "enabled" and results["ssh_validate"].ok and ssh_values_available and all(ssh[key].lower() == expected for key, expected in ssh_required.items())
        else "UNKNOWN"
        if service_ssh is None or enabled_ssh is None or not ssh_values_available
        else "FAIL"
    )
    fail2ban_status = (
        "PASS"
        if service_f2b == "active" and fail2ban["status"] == "PASS"
        else "UNKNOWN"
        if service_f2b is None or fail2ban["status"] == "UNKNOWN"
        else "FAIL"
    )
    warnings = [item for item in (
        permission_warning(results, ("ssh_service", "ssh_enabled", "ssh_config", "ssh_validate")),
        permission_warning(results, ("ufw_status",)),
        permission_warning(results, ("fail2ban_service", "fail2ban_status", "fail2ban_sshd")),
        permission_warning(results, ("testuser_read",)),
    ) if item]
    cards = [
        {"id": "ssh", "label": "SSH", "value": ssh_status, "detail": ssh.get("passwordauthentication") or ("Cần xác thực sudo" if ssh_status == "UNKNOWN" else "Chưa đọc được cấu hình")},
        {"id": "ufw", "label": "UFW Firewall", "value": ufw["status"], "detail": f'{len(ufw["rules"])} rule đang đọc được' if ufw["status"] != "UNKNOWN" else "Cần xác thực sudo"},
        {"id": "fail2ban", "label": "Fail2ban", "value": fail2ban_status, "detail": fail2ban.get("jail") or ("Cần xác thực sudo" if fail2ban_status == "UNKNOWN" else "Chưa có jail")},
        {"id": "permissions", "label": "File permissions", "value": permissions["status"], "detail": f'Mode {permissions["mode"] or "?"}' if permissions["status"] != "UNKNOWN" else "Cần xác thực sudo"},
    ]
    return {
        "collected_at": now_iso(),
        "system": {
            "hostname": hostname,
            "os": os_info.get("PRETTY_NAME") or None,
            "version_id": os_info.get("VERSION_ID") or None,
            "architecture": result_value(results["architecture"]),
            "kernel": result_value(results["kernel"]),
            "memory": first_line(results["memory"].stdout) or None,
            "disk": first_line(results["disk"].stdout) or None,
            "ips": redact_ips(results["ip_addresses"].stdout),
        },
        "overall": "PASS" if all(card["value"] == "PASS" for card in cards) else ("UNKNOWN" if any(card["value"] == "UNKNOWN" for card in cards) else "FAIL"),
        "warnings": warnings,
        "cards": cards,
        "ssh": {
            "status": ssh_status,
            "service": service_ssh,
            "enabled": enabled_ssh,
            "validation": "PASS" if results["ssh_validate"].ok else ("UNKNOWN" if results["ssh_validate"].returncode == 127 else "FAIL"),
            "config": ssh,
            "warning": permission_warning(results, ("ssh_service", "ssh_enabled", "ssh_config", "ssh_validate")),
        },
        "ufw": {**ufw, "warning": permission_warning(results, ("ufw_status",))},
        "fail2ban": {"status": fail2ban_status, "service": service_f2b, **fail2ban, "warning": permission_warning(results, ("fail2ban_service", "fail2ban_status", "fail2ban_sshd"))},
        "permissions": {**permissions, "warning": permission_warning(results, ("testuser_read",))},
        "updates": updates,
        "commands": {key: " ".join(shlex.quote(part) for part in runner.command_for(key)) for key in runner.registry},
    }


def load_test_cases() -> list[dict[str, str]]:
    import csv
    try:
        with TEST_CASES_FILE.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    except (OSError, csv.Error):
        return []


def list_reports() -> list[dict[str, object]]:
    reports = []
    try:
        paths = sorted(REPORT_DIR.glob("security_audit_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        paths = []
    for path in paths:
        try:
            stat = path.stat()
            reports.append({"name": path.name, "size": stat.st_size, "modified": datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds")})
        except OSError:
            continue
    return reports


def report_path(name: str) -> Path | None:
    if not re.fullmatch(r"security_audit_\d{8}_\d{6}\.txt", name):
        return None
    candidate = (REPORT_DIR / name).resolve()
    try:
        candidate.relative_to(REPORT_DIR.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None
