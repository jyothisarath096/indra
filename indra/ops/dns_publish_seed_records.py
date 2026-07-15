#!/usr/bin/env python3
"""Publish INDRA DNS seed A records from on-chain validator addresses.

This is an operational automation tool, not consensus logic. DNS seeds are a
cache of chain state: the source of truth is `indra_getValidatorSet`, whose
active validators may publish strict IP:port `network_addr` values on-chain.

The tool is dry-run by default. Use `--apply` to write Cloudflare changes.
Cloudflare credentials are accepted only through a restricted-permission file
or an environment variable; never pass API tokens as command-line arguments.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol


DEFAULT_RECORD_NAMES = ("seeds.indraprotocol.com", "seeds2.indraprotocol.com")
DEFAULT_TTL = 300
DEFAULT_COMMENT = "managed by indra-dns-publish from indra_getValidatorSet"
DEFAULT_TOKEN_ENV = "CLOUDFLARE_API_TOKEN"
CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"


class DnsPublishError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class DesiredRecord:
    name: str
    content: str
    ttl: int = DEFAULT_TTL
    proxied: bool = False
    comment: str = DEFAULT_COMMENT


@dataclass(frozen=True)
class CloudflareRecord:
    id: str
    name: str
    type: str
    content: str
    ttl: int | None = None
    proxied: bool | None = None
    comment: str | None = None


@dataclass(frozen=True)
class DnsChange:
    action: str
    name: str
    content: str
    record_id: str | None = None
    reason: str = ""
    desired: DesiredRecord | None = None


class CloudflareClient(Protocol):
    def list_a_records(self, names: Iterable[str]) -> list[CloudflareRecord]:
        ...

    def create_a_record(self, record: DesiredRecord) -> None:
        ...

    def update_a_record(self, record_id: str, record: DesiredRecord) -> None:
        ...

    def delete_record(self, record_id: str) -> None:
        ...


def rpc_call(rpc_url: str, method: str, params: list[Any] | None = None) -> Any:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
    ).encode("utf-8")
    request = urllib.request.Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise DnsPublishError(f"RPC request failed: {exc}") from exc

    if "error" in payload:
        raise DnsPublishError(f"RPC returned error: {payload['error']}")
    return payload.get("result")


def fetch_validator_set(rpc_url: str) -> Mapping[str, Any]:
    result = rpc_call(rpc_url, "indra_getValidatorSet", [])
    if not isinstance(result, dict):
        raise DnsPublishError("indra_getValidatorSet returned a non-object result")
    return result


def ipv4_from_network_addr(addr: str) -> str:
    if not isinstance(addr, str) or not addr:
        raise ValueError("network_addr must be a non-empty string")
    host, port = split_ip_port(addr)
    if int(port) <= 0:
        raise ValueError("network_addr port must be non-zero")
    ip = ipaddress.ip_address(host)
    if ip.version != 4:
        raise ValueError("only IPv4 network_addr values can be published as A records")
    return str(ip)


def split_ip_port(addr: str) -> tuple[str, str]:
    if addr.startswith("["):
        end = addr.find("]")
        if end == -1 or end + 1 >= len(addr) or addr[end + 1] != ":":
            raise ValueError("invalid bracketed IPv6 socket address")
        return addr[1:end], addr[end + 2 :]
    if addr.count(":") != 1:
        raise ValueError("network_addr must be IPv4:port for DNS A publishing")
    return tuple(addr.rsplit(":", 1))  # type: ignore[return-value]


def derive_desired_a_records(
    validator_set: Mapping[str, Any],
    record_names: Iterable[str],
    *,
    min_expected_validators: int,
) -> list[DesiredRecord]:
    validators = validator_set.get("validators")
    if not isinstance(validators, list):
        raise DnsPublishError("validator set response is missing validators[]")
    if len(validators) < min_expected_validators:
        raise DnsPublishError(
            f"refusing to publish: validator set has {len(validators)} validators, "
            f"below --min-expected-validators={min_expected_validators}"
        )

    ips: set[str] = set()
    skipped = 0
    for validator in validators:
        if not isinstance(validator, dict):
            raise DnsPublishError("validator set contains a non-object validator entry")
        addr = validator.get("network_addr")
        if addr is None:
            skipped += 1
            continue
        try:
            ips.add(ipv4_from_network_addr(addr))
        except ValueError as exc:
            raise DnsPublishError(
                f"validator {validator.get('validator_id', '<unknown>')} has invalid "
                f"network_addr for A-record publishing: {addr!r}: {exc}"
            ) from exc

    if not ips:
        raise DnsPublishError(
            "refusing to publish: no active validator has an IPv4 network_addr"
        )

    desired = [
        DesiredRecord(name=name.rstrip(".").lower(), content=ip)
        for name in record_names
        for ip in sorted(ips, key=ipaddress.IPv4Address)
    ]
    if not desired:
        raise DnsPublishError("refusing to publish: no DNS record names configured")
    if skipped:
        print(
            f"[warn] {skipped} active validators had network_addr=null and were skipped",
            file=sys.stderr,
        )
    return desired


def compute_dns_diff(
    existing_records: Iterable[CloudflareRecord],
    desired_records: Iterable[DesiredRecord],
) -> list[DnsChange]:
    desired_by_key = {(r.name.lower(), r.content): r for r in desired_records}
    existing_by_key: dict[tuple[str, str], list[CloudflareRecord]] = {}
    changes: list[DnsChange] = []

    for record in existing_records:
        if record.type != "A":
            continue
        existing_by_key.setdefault((record.name.lower(), record.content), []).append(record)

    for key, desired in sorted(desired_by_key.items()):
        records = existing_by_key.get(key, [])
        if not records:
            changes.append(
                DnsChange(
                    action="create",
                    name=desired.name,
                    content=desired.content,
                    desired=desired,
                    reason="missing desired A record",
                )
            )
            continue

        keeper = sorted(records, key=lambda r: r.id)[0]
        if (
            keeper.ttl != desired.ttl
            or keeper.proxied is not False
            or (keeper.comment or "") != desired.comment
        ):
            changes.append(
                DnsChange(
                    action="update",
                    name=desired.name,
                    content=desired.content,
                    record_id=keeper.id,
                    desired=desired,
                    reason="record metadata differs",
                )
            )
        for duplicate in sorted(records, key=lambda r: r.id)[1:]:
            changes.append(
                DnsChange(
                    action="delete",
                    name=duplicate.name,
                    content=duplicate.content,
                    record_id=duplicate.id,
                    reason="duplicate managed A record",
                )
            )

    for key, records in sorted(existing_by_key.items()):
        if key in desired_by_key:
            continue
        for record in sorted(records, key=lambda r: r.id):
            changes.append(
                DnsChange(
                    action="delete",
                    name=record.name,
                    content=record.content,
                    record_id=record.id,
                    reason="stale A record not present in active validator set",
                )
            )
    return changes


def apply_changes(client: CloudflareClient, changes: Iterable[DnsChange]) -> None:
    for change in changes:
        if change.action == "create":
            assert change.desired is not None
            client.create_a_record(change.desired)
        elif change.action == "update":
            assert change.record_id is not None and change.desired is not None
            client.update_a_record(change.record_id, change.desired)
        elif change.action == "delete":
            assert change.record_id is not None
            client.delete_record(change.record_id)
        else:
            raise DnsPublishError(f"unknown DNS change action: {change.action}")


class UrlLibCloudflareClient:
    def __init__(self, zone_id: str, token: str, api_base: str = CLOUDFLARE_API_BASE):
        self.zone_id = zone_id
        self.token = token
        self.api_base = api_base.rstrip("/")

    def list_a_records(self, names: Iterable[str]) -> list[CloudflareRecord]:
        records: list[CloudflareRecord] = []
        for name in names:
            query = urllib.parse.urlencode({"type": "A", "name": name.rstrip(".")})
            result = self._request("GET", f"/zones/{self.zone_id}/dns_records?{query}")
            for raw in result:
                records.append(parse_cloudflare_record(raw))
        return records

    def create_a_record(self, record: DesiredRecord) -> None:
        self._request("POST", f"/zones/{self.zone_id}/dns_records", record_payload(record))

    def update_a_record(self, record_id: str, record: DesiredRecord) -> None:
        self._request(
            "PUT", f"/zones/{self.zone_id}/dns_records/{record_id}", record_payload(record)
        )

    def delete_record(self, record_id: str) -> None:
        self._request("DELETE", f"/zones/{self.zone_id}/dns_records/{record_id}")

    def _request(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.api_base + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise DnsPublishError(f"Cloudflare API request failed: {exc}") from exc
        if not payload.get("success"):
            raise DnsPublishError(f"Cloudflare API error: {payload.get('errors')}")
        return payload.get("result", [])


def parse_cloudflare_record(raw: Mapping[str, Any]) -> CloudflareRecord:
    return CloudflareRecord(
        id=str(raw["id"]),
        name=str(raw["name"]).rstrip(".").lower(),
        type=str(raw["type"]),
        content=str(raw["content"]),
        ttl=raw.get("ttl") if isinstance(raw.get("ttl"), int) else None,
        proxied=raw.get("proxied") if isinstance(raw.get("proxied"), bool) else None,
        comment=raw.get("comment") if isinstance(raw.get("comment"), str) else None,
    )


def record_payload(record: DesiredRecord) -> dict[str, Any]:
    return {
        "type": "A",
        "name": record.name,
        "content": record.content,
        "ttl": record.ttl,
        "proxied": record.proxied,
        "comment": record.comment,
    }


def read_token_from_file(path: str) -> str:
    st = os.stat(path)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise DnsPublishError(
            f"refusing to read Cloudflare token file {path}: permissions must not allow group/other access"
        )
    with open(path, "r", encoding="utf-8") as fh:
        token = fh.read().strip()
    if not token:
        raise DnsPublishError("Cloudflare token file is empty")
    return token


def load_cloudflare_token(args: argparse.Namespace) -> str:
    if args.token_file:
        return read_token_from_file(args.token_file)
    token = os.environ.get(args.token_env, "").strip()
    if token:
        return token
    raise DnsPublishError(
        f"missing Cloudflare API token: set --token-file or environment variable {args.token_env}"
    )


def print_plan(changes: list[DnsChange], *, dry_run: bool) -> None:
    prefix = "DRY RUN" if dry_run else "APPLY"
    if not changes:
        print(f"[{prefix}] DNS seed records are already up to date; no changes.")
        return
    print(f"[{prefix}] planned DNS changes: {len(changes)}")
    for change in changes:
        rid = f" id={change.record_id}" if change.record_id else ""
        print(
            f"  - {change.action.upper()} {change.name} A {change.content}{rid}"
            f" ({change.reason})"
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Publish Cloudflare DNS seed A records from indra_getValidatorSet"
    )
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8545")
    parser.add_argument("--zone-id", required=True)
    parser.add_argument(
        "--record-name",
        action="append",
        default=[],
        help="Seed DNS name to manage; repeatable. Defaults to both public seed names.",
    )
    parser.add_argument("--token-file")
    parser.add_argument("--token-env", default=DEFAULT_TOKEN_ENV)
    parser.add_argument("--min-expected-validators", type=int, default=1)
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    parser.add_argument("--apply", action="store_true", help="Actually write Cloudflare changes")
    parser.add_argument(
        "--allow-destructive",
        action="store_true",
        help="Allow deletion of stale/duplicate managed A records when applying",
    )
    args = parser.parse_args(argv)
    if args.min_expected_validators < 1:
        parser.error("--min-expected-validators must be at least 1")
    if args.ttl < 60 and args.ttl != 1:
        parser.error("--ttl must be 1 (Cloudflare automatic) or at least 60")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    record_names = args.record_name or list(DEFAULT_RECORD_NAMES)
    try:
        validator_set = fetch_validator_set(args.rpc_url)
        desired = [
            DesiredRecord(r.name, r.content, args.ttl, r.proxied, r.comment)
            for r in derive_desired_a_records(
                validator_set,
                record_names,
                min_expected_validators=args.min_expected_validators,
            )
        ]

        token = load_cloudflare_token(args)
        client = UrlLibCloudflareClient(args.zone_id, token)
        existing = client.list_a_records(record_names)
        changes = compute_dns_diff(existing, desired)

        if args.apply and not args.allow_destructive:
            destructive = [c for c in changes if c.action == "delete"]
            if destructive:
                print_plan(changes, dry_run=False)
                raise DnsPublishError(
                    "refusing to delete DNS records without --allow-destructive"
                )

        print_plan(changes, dry_run=not args.apply)
        if args.apply:
            apply_changes(client, changes)
            print("[APPLY] complete")
        else:
            print("[DRY RUN] no Cloudflare records were changed")
        return 0
    except DnsPublishError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
