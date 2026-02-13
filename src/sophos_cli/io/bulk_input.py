"""Bulk input parsing for DNS commands."""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from typing import Any, Literal

from sophos_cli.models.dns import DnsHostAddress, DnsHostEntryCreate, DnsHostEntryUpdate

BulkInputFormat = Literal["auto", "json", "csv"]


def load_dns_add_entries(
    source: str,
    input_format: BulkInputFormat = "auto",
) -> list[DnsHostEntryCreate]:
    """Load DNS add records from a JSON/CSV file or stdin."""

    records = _load_records(source, input_format)
    return [DnsHostEntryCreate.model_validate(record) for record in records]


def load_dns_update_entries(
    source: str,
    input_format: BulkInputFormat = "auto",
) -> list[DnsHostEntryUpdate]:
    """Load DNS update records from a JSON/CSV file or stdin."""

    records = _load_records(source, input_format)
    return [DnsHostEntryUpdate.model_validate(record) for record in records]


def _load_records(source: str, input_format: BulkInputFormat) -> list[dict[str, Any]]:
    text = _read_text(source)
    resolved_format = _resolve_format(source, text, input_format)

    if resolved_format == "json":
        records = _parse_json(text)
    else:
        records = _parse_csv(text)

    if not records:
        raise ValueError("Input data did not contain any records")
    return [_canonicalize_record(record) for record in records]


def _read_text(source: str) -> str:
    if source == "-":
        content = sys.stdin.read()
    else:
        content = Path(source).read_text(encoding="utf-8")

    if not content.strip():
        raise ValueError("Input is empty")
    return content


def _resolve_format(
    source: str,
    text: str,
    input_format: BulkInputFormat,
) -> Literal["json", "csv"]:
    if input_format in {"json", "csv"}:
        return input_format

    if source != "-":
        suffix = Path(source).suffix.lower()
        if suffix == ".json":
            return "json"
        if suffix == ".csv":
            return "csv"

    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        return "json"
    return "csv"


def _parse_json(text: str) -> list[dict[str, Any]]:
    payload = json.loads(text)
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict) and isinstance(payload.get("entries"), list):
        records = payload["entries"]
    else:
        raise ValueError("JSON input must be a list of records or an object with an 'entries' list")

    if not all(isinstance(record, dict) for record in records):
        raise ValueError("All JSON records must be objects")
    return records


def _parse_csv(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV input must include a header row")

    records = []
    for row in reader:
        if row is None:
            continue
        records.append({key: value for key, value in row.items() if key})
    return records


def _canonicalize_record(record: dict[str, Any]) -> dict[str, Any]:
    canonical: dict[str, Any] = {}

    host_name = _pick(record, ["host_name", "hostname", "HostName", "name", "Name"])
    if host_name is not None:
        canonical["host_name"] = str(host_name).strip()

    reverse_lookup = _pick(
        record,
        [
            "add_reverse_dns_lookup",
            "addReverseDnsLookup",
            "AddReverseDNSLookUp",
            "reverse_dns_lookup",
            "reverseLookup",
        ],
    )
    parsed_reverse = _parse_optional_bool(reverse_lookup)
    if parsed_reverse is not None:
        canonical["add_reverse_dns_lookup"] = parsed_reverse

    addresses = _parse_addresses(record)
    if addresses:
        canonical["addresses"] = addresses

    return canonical


def _parse_addresses(record: dict[str, Any]) -> list[DnsHostAddress]:
    if isinstance(record.get("addresses"), list):
        addresses: list[DnsHostAddress] = []
        for item in record["addresses"]:
            if not isinstance(item, dict):
                continue
            normalized = _canonicalize_address(item)
            if normalized:
                addresses.append(DnsHostAddress.model_validate(normalized))
        return addresses

    normalized = _canonicalize_address(record)
    if normalized:
        return [DnsHostAddress.model_validate(normalized)]
    return []


def _canonicalize_address(record: dict[str, Any]) -> dict[str, Any]:
    canonical: dict[str, Any] = {}

    ip_address = _pick(record, ["ip_address", "IPAddress", "address", "ip"])
    if ip_address is None or str(ip_address).strip() == "":
        return canonical
    canonical["ip_address"] = str(ip_address).strip()

    entry_type = _pick(record, ["entry_type", "EntryType"])
    if entry_type is not None and str(entry_type).strip() != "":
        canonical["entry_type"] = str(entry_type).strip()

    ip_family = _pick(record, ["ip_family", "IPFamily"])
    if ip_family is not None and str(ip_family).strip() != "":
        canonical["ip_family"] = str(ip_family).strip()

    ttl = _pick(record, ["ttl", "TTL"])
    parsed_ttl = _parse_optional_int(ttl)
    if parsed_ttl is not None:
        canonical["ttl"] = parsed_ttl

    weight = _pick(record, ["weight", "Weight"])
    parsed_weight = _parse_optional_int(weight)
    if parsed_weight is not None:
        canonical["weight"] = parsed_weight

    publish = _pick(record, ["publish_on_wan", "PublishOnWAN"])
    parsed_publish = _parse_optional_publish(publish)
    if parsed_publish is not None:
        canonical["publish_on_wan"] = parsed_publish

    return canonical


def _pick(source: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key in source:
            return source[key]
    return None


def _parse_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if text == "":
        return None
    return int(text)


def _parse_optional_bool(value: Any) -> bool | None:
    if value is None:
        return None

    text = str(value).strip().lower()
    if text == "":
        return None
    if text in {"true", "1", "yes", "y", "enable"}:
        return True
    if text in {"false", "0", "no", "n", "disable"}:
        return False

    raise ValueError(f"Unsupported boolean value: {value}")


def _parse_optional_publish(value: Any) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    if text == "":
        return None

    lowered = text.lower()
    if lowered in {"enable", "enabled", "true", "1", "yes"}:
        return "Enable"
    if lowered in {"disable", "disabled", "false", "0", "no"}:
        return "Disable"

    raise ValueError(f"Unsupported PublishOnWAN value: {value}")
