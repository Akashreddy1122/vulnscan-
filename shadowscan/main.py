"""ShadowScan command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import stat
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from shadowscan.core.config import load_config
from shadowscan.core.engine import Engine
from shadowscan.core.errors import ShadowScanError, ConfigurationError
from shadowscan.core.plugin_loader import PLUGINS, PROFILES, select_plugins
from shadowscan.core.external_plugins import discover
from shadowscan.core.target import expand_targets
from shadowscan.database.db_manager import Database
from shadowscan.database.cve_cache import import_nvd
from shadowscan.database.scheduler import schedule, due_jobs, complete
from shadowscan.reporting.report_generator import export
from shadowscan.reporting.delta import compare

BANNER = "ShadowScan 0.2 | Authorized security testing only"
DISCLAIMER = "Only scan assets you own or have explicit written permission to assess."


def parser() -> argparse.ArgumentParser:
    """Define CLI without side effects."""
    p = argparse.ArgumentParser(prog="shadowscan", description=DISCLAIMER)
    p.add_argument(
        "-t",
        "--target",
        action="append",
        help="IP, CIDR, host, URL, file or - for stdin",
    )
    p.add_argument(
        "--authorized",
        action="store_true",
        help="I confirm I am authorized to scan these targets",
    )
    p.add_argument("--profile", choices=PROFILES, default=None)
    p.add_argument(
        "--full-scan", action="store_true", help="Use full implemented plugin profile"
    )
    p.add_argument("--web-scan", action="store_true")
    p.add_argument("--port-scan", action="store_true")
    p.add_argument("--recon-only", action="store_true")
    p.add_argument("--modules", help="Comma-separated module names")
    modes = p.add_mutually_exclusive_group()
    modes.add_argument(
        "--passive", action="store_true", help="Offline only; no network requests"
    )
    modes.add_argument(
        "--aggressive", action="store_true", help="Use full implemented plugin profile"
    )
    modes.add_argument(
        "--stealth", action="store_true", help="Slow pacing (not IDS evasion)"
    )
    p.add_argument("--config", help="YAML or JSON configuration")
    p.add_argument("--threads", type=int)
    p.add_argument(
        "--delay", type=float, help="Additional minimum seconds between requests"
    )
    p.add_argument(
        "--ports", help="Comma-separated TCP ports or ranges, e.g. 80,443,8000-8010"
    )
    p.add_argument(
        "--include-subdomains",
        action="store_true",
        help="Explicitly authorize DNS-only subdomain enumeration",
    )
    p.add_argument("--udp-ports", help="Explicitly probe up to 64 UDP ports")
    p.add_argument(
        "--all-ports",
        action="store_true",
        help="Explicitly test all 65535 TCP ports on ONE target",
    )
    p.add_argument("--proxy", help="HTTP(S)/SOCKS4/SOCKS5 proxy URL")
    p.add_argument("--proxy-list", help="File of up to 50 HTTP(S) proxy URLs to rotate")
    p.add_argument(
        "--allow-insecure-auth",
        action="store_true",
        help="Explicitly allow credentials over plaintext HTTP (unsafe)",
    )
    p.add_argument(
        "--auth-cookie",
        help="Session Cookie header; never persisted (visible in shell history)",
    )
    p.add_argument("--output", help="Report filename")
    p.add_argument(
        "--format", choices=("html", "pdf", "json", "xml", "csv"), default="html"
    )
    p.add_argument("--db", default="shadowscan.db", help="SQLite checkpoint database")
    p.add_argument(
        "--resume", help="Resume an existing scan ID using the saved targets"
    )
    p.add_argument(
        "--compare",
        metavar="SCAN_ID",
        help="Write a delta against an earlier saved scan",
    )
    p.add_argument("--list-modules", action="store_true")
    p.add_argument(
        "--enable-third-party",
        action="store_true",
        help="Load trusted installed entry-point plugins (arbitrary code)",
    )
    p.add_argument(
        "--update-db",
        metavar="NVD_JSON",
        help="Import a local NVD 2.0 JSON file offline",
    )
    p.add_argument(
        "--schedule-at", metavar="ISO_DATE", help="Queue a future scan with timezone"
    )
    p.add_argument(
        "--repeat-hours", type=int, help="Repeat a scheduled scan every N hours"
    )
    p.add_argument(
        "--run-due", action="store_true", help="Run due jobs once (cron-friendly)"
    )
    p.add_argument(
        "--serve", action="store_true", help="Run authenticated scanner REST API"
    )
    p.add_argument(
        "--api-token-env",
        default="SHADOWSCAN_API_TOKEN",
        help="API bearer token environment variable",
    )
    p.add_argument(
        "--api-bind", default="127.0.0.1", help="API bind host (default localhost)"
    )
    p.add_argument("--api-port", type=int, default=8787, help="API port")
    p.add_argument(
        "--jwt-env",
        metavar="ENV_NAME",
        help="Inspect a JWT from an environment variable offline",
    )
    p.add_argument(
        "--auth-digest-env",
        metavar="ENV_NAME",
        help="Environment variable containing Digest user:password",
    )
    p.add_argument(
        "--auth-basic-env",
        metavar="ENV_NAME",
        help="Environment variable containing user:password (never stored)",
    )
    p.add_argument(
        "--auth-bearer-env",
        metavar="ENV_NAME",
        help="Environment variable containing bearer token (never stored)",
    )
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--quiet", action="store_true")
    return p


def parse_ports(value: str) -> list[int]:
    """Parse bounded explicit TCP port ranges."""
    result: list[int] = []
    try:
        for segment in value.split(","):
            if "-" in segment:
                start, end = map(int, segment.split("-"))
                if end < start or end - start > 1023:
                    raise ValueError("Reversed or overly large range")
                result.extend(range(start, end + 1))
            else:
                result.append(int(segment))
    except ValueError as exc:
        raise ConfigurationError(f"Invalid port list: {exc}") from exc
    if (
        not result
        or len(result) > 1024
        or any(not 1 <= port <= 65535 for port in result)
    ):
        raise ConfigurationError("Use 1-1024 valid ports in the range 1-65535")
    return list(dict.fromkeys(result))


class PrivateRotatingFileHandler(RotatingFileHandler):
    """Create current and rotated log files with private permissions."""

    def _open(self):
        """Refuse symlinks and use mode 0600 before the first log write."""
        if Path(self.baseFilename).is_symlink():
            raise ConfigurationError("Refusing a symlinked log file")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.baseFilename, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ConfigurationError("Log must be a regular, non-hardlinked file")
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            return os.fdopen(fd, self.mode, encoding=self.encoding, errors=self.errors)
        except BaseException:
            os.close(fd)
            raise


def setup_logging(verbose: bool, quiet: bool) -> None:
    """Configure console and bounded local log without credentials."""
    root = logging.getLogger()
    root.setLevel(logging.WARNING)
    logging.getLogger("shadowscan").setLevel(logging.DEBUG if verbose else logging.INFO)
    console = RichHandler(
        console=Console(stderr=True), show_time=False, show_path=False
    )
    console.setLevel(
        logging.ERROR if quiet else logging.DEBUG if verbose else logging.INFO
    )
    root.addHandler(console)
    file_handler = PrivateRotatingFileHandler(
        "shadowscan.log", maxBytes=1024 * 1024, backupCount=2
    )
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root.addHandler(file_handler)


async def execute(args: argparse.Namespace) -> int:
    """Validate consent and configuration before any network access."""
    if args.serve:
        from shadowscan.api.server import serve

        token = os.environ.get(args.api_token_env, "")
        if not 1 <= args.api_port <= 65535:
            raise ConfigurationError("API port must be 1-65535")
        await serve(token, args.db, args.api_bind, args.api_port)
        return 0
    if args.list_modules:
        registry = (
            {**PLUGINS, **discover(set(PLUGINS))}
            if args.enable_third_party
            else PLUGINS
        )
        for name, cls in registry.items():
            print(
                f"{name:16} {cls.group:8} {'active' if cls.active else 'response analysis'}"
            )
        return 0
    if args.update_db:
        db = Database(args.db)
        try:
            count = import_nvd(db.conn, args.update_db)
            print(f"Imported {count} exact CPE/CVE records from local NVD JSON")
            return 0
        finally:
            db.close()
    if args.repeat_hours and not args.schedule_at:
        raise ConfigurationError("--repeat-hours requires --schedule-at")
    if args.schedule_at and args.run_due:
        raise ConfigurationError("Choose scheduling or running due jobs")
    config = load_config(args.config)
    if args.allow_insecure_auth:
        if not args.authorized:
            raise ConfigurationError(
                "--allow-insecure-auth requires explicit --authorized"
            )
        config["allow_insecure_auth"] = True
    if args.threads is not None:
        if not 1 <= args.threads <= 200:
            raise ConfigurationError("threads must be 1-200")
        config["threads"] = args.threads
    if args.include_subdomains:
        if not args.authorized:
            raise ConfigurationError(
                "Subdomain enumeration requires explicit --authorized"
            )
        config["enumerate_subdomains"] = True
    if args.udp_ports:
        config["udp_ports"] = parse_ports(args.udp_ports)
        if len(config["udp_ports"]) > 64:
            raise ConfigurationError("UDP port limit is 64")
    if args.ports and args.all_ports:
        raise ConfigurationError("Choose --ports or --all-ports")
    if args.ports:
        config["ports"] = parse_ports(args.ports)
    if args.all_ports:
        if args.run_due or args.schedule_at:
            raise ConfigurationError("--all-ports cannot be used with scheduled jobs")
        if not (
            args.port_scan
            or args.full_scan
            or args.modules
            and "ports" in args.modules.split(",")
        ):
            raise ConfigurationError(
                "--all-ports requires --port-scan, --full-scan or --modules ports"
            )
        if not args.authorized:
            raise ConfigurationError("--all-ports requires explicit --authorized")
        config["ports"] = list(range(1, 65536))
    if args.delay is not None:
        if not 0 <= args.delay <= 60:
            raise ConfigurationError("delay must be 0-60 seconds")
        config["rate"] = min(config["rate"], 1 / max(args.delay, 0.01))
    if args.stealth:
        config["rate"] = min(config["rate"], 0.2)
        config["jitter"] = max(config["jitter"], 1.0)
    mode = (
        "passive"
        if args.passive
        else "stealth"
        if args.stealth
        else "aggressive"
        if args.aggressive
        else config["mode"]
    )
    profile = (
        "full"
        if args.full_scan or args.aggressive
        else "web"
        if args.web_scan
        else "network"
        if args.port_scan
        else "recon"
        if args.recon_only
        else args.profile or config["profile"]
    )
    modules = (
        [item.strip() for item in args.modules.split(",") if item.strip()]
        if args.modules
        else (["ports", "udp_ports"] if config["udp_ports"] else ["ports"])
        if args.port_scan
        else ["udp_ports"]
        if args.udp_ports
        else None
    )
    if (
        sum(
            bool(value)
            for value in (
                args.auth_basic_env,
                args.auth_digest_env,
                args.auth_bearer_env,
            )
        )
        > 1
    ):
        raise ConfigurationError("Choose Basic, Digest or Bearer authentication")

    def from_env(name: str | None) -> tuple[str, str] | None:
        """Load user:password from an environment variable without persistence."""
        if not name:
            return None
        value = os.environ.get(name, "")
        if ":" not in value:
            raise ConfigurationError(
                "Authentication variable must contain user:password"
            )
        return tuple(value.split(":", 1))

    basic = from_env(args.auth_basic_env)
    digest = from_env(args.auth_digest_env)
    proxy_list = None
    if args.proxy_list:
        if args.proxy:
            raise ConfigurationError("Choose --proxy or --proxy-list")
        proxy_file = Path(args.proxy_list)
        if proxy_file.stat().st_size > 8192:
            raise ConfigurationError("Proxy file exceeds 8 KiB")
        proxy_list = [
            line.strip()
            for line in proxy_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not proxy_list:
            raise ConfigurationError("Proxy list is empty")
    bearer = os.environ.get(args.auth_bearer_env) if args.auth_bearer_env else None
    if args.auth_bearer_env and not bearer:
        raise ConfigurationError("Bearer auth environment variable is missing or empty")
    jwt_token = os.environ.get(args.jwt_env) if args.jwt_env else None
    if args.jwt_env and not jwt_token:
        raise ConfigurationError("JWT environment variable is missing or empty")
    db = Database(args.db)
    try:
        if args.run_due:
            if not args.authorized:
                raise ConfigurationError("--run-due requires --authorized")
            jobs = due_jobs(db.conn)
            for job in jobs:
                plugins = select_plugins(
                    job["profile"],
                    disabled=config["modules_disabled"],
                    mode=job["mode"],
                    external=args.enable_third_party,
                )
                result = await Engine(
                    config,
                    db,
                    plugins,
                    args.proxy,
                    args.auth_cookie,
                    basic,
                    bearer,
                    jwt_token,
                    digest,
                    proxy_list,
                ).run(job["targets"], job["mode"], job["profile"])
                output = (
                    f"scheduled_{job['job_id'][:8]}_{result.scan_id[:8]}.{args.format}"
                )
                export(result, output, args.format)
                if job["previous_scan"]:
                    delta = compare(db.load(job["previous_scan"]), result)
                    delta_path = Path(output + ".delta.json")
                    delta_path.write_text(json.dumps(delta, indent=2), encoding="utf-8")
                    delta_path.chmod(0o600)
                complete(db.conn, job, result.scan_id)
                print(f"Scheduled job {job['job_id']}: report {output}")
            if not jobs:
                print("No jobs are due")
            return 0
        resume = db.load(args.resume) if args.resume else None
        targets = (
            resume.targets
            if resume
            else expand_targets(args.target or [], config["max_targets"])
        )
        if args.all_ports and len(targets) != 1:
            raise ConfigurationError("--all-ports is limited to one explicit target")
        if not args.authorized:
            if not sys.stdin.isatty():
                raise ConfigurationError(
                    "--authorized required for non-interactive use"
                )
            response = input(
                f"{DISCLAIMER}\nConfirm permission for {len(targets)} target(s) [yes/no]: "
            )
            if response.strip().lower() != "yes":
                raise ConfigurationError("Authorization not confirmed")
        if resume:
            mode, profile = resume.mode, resume.profile
        if args.schedule_at:
            if args.resume:
                raise ConfigurationError("Cannot schedule an existing scan ID")
            job_id = schedule(
                db.conn, targets, mode, profile, args.schedule_at, args.repeat_hours
            )
            print(f"Scheduled job {job_id}; run due jobs with --run-due --authorized")
            return 0
        plugins = select_plugins(
            profile,
            modules,
            config["modules_disabled"],
            mode,
            external=args.enable_third_party,
        )
        engine = Engine(
            config,
            db,
            plugins,
            args.proxy,
            args.auth_cookie,
            basic,
            bearer,
            jwt_token,
            digest,
            proxy_list,
        )
        if sys.stderr.isatty() and not args.quiet:
            with Progress(
                SpinnerColumn(),
                TextColumn("Scanning authorized targets"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=Console(stderr=True),
            ) as progress:
                task = progress.add_task(
                    "scan",
                    total=len(targets),
                    completed=len(resume.completed) if resume else 0,
                )
                engine.on_progress = lambda done, total: progress.update(
                    task, completed=done
                )
                result = await engine.run(targets, mode, profile, resume)
        else:
            result = await engine.run(targets, mode, profile, resume)
        output = args.output or f"report_{result.scan_id[:8]}.{args.format}"
        export(result, output, args.format)
        if args.compare:
            old = db.load(args.compare)
            delta = compare(old, result)
            delta_path = Path(output + ".delta.json")
            delta_path.write_text(json.dumps(delta, indent=2), encoding="utf-8")
            delta_path.chmod(0o600)
            print(
                f"Delta: {len(delta['new'])} new; {len(delta['resolved'])} resolved; {delta_path}"
            )
        print(
            f"Scan {result.scan_id}: {len(result.findings)} observations, {len(result.errors)} errors. Report: {output}"
        )
        return 0 if not result.errors else 1
    finally:
        db.close()


def main() -> None:
    """Run the CLI, reporting validation failures without traceback."""
    args = parser().parse_args()
    if not args.quiet:
        print(BANNER + "\n" + DISCLAIMER, file=sys.stderr)
    try:
        setup_logging(args.verbose, args.quiet)
        sys.exit(asyncio.run(execute(args)))
    except (ShadowScanError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
