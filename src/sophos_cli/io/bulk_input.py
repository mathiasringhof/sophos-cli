"""Bulk input parsing for DNS commands."""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from typing import Literal, cast

from sophos_cli.models.dns import DnsHostAddress, DnsHostEntryCreate, DnsHostEntryUpdate

BulkInputFormat = Literal["auto", "json", "csv"]
Record = dict[str, object]


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


def _load_records(source: str, input_format: BulkInputFormat) -> list[Record]:
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
    if input_format == "json":
        return "json"
    if input_format == "csv":
        return "csv"

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


def _parse_json(text: str) -> list[Record]:
    payload: object = json.loads(text)
    raw_records: list[object]

    if isinstance(payload, list):
        raw_records = cast(list[object], payload)
    else:
        payload_dict = _normalize_record(payload)
        if payload_dict is None:
            raise ValueError(
                "JSON input must be a list of records or an object with an 'entries' list"
            )
        entries = payload_dict.get("entries")
        if not isinstance(entries, list):
            raise ValueError(
                "JSON input must be a list of records or an object with an 'entries' list"
            )
        raw_records = cast(list[object], entries)

    records: list[Record] = []
    for raw_record in raw_records:
        record = _normalize_record(raw_record)
        if record is None:
            raise ValueError("All JSON records must be objects with string keys")
        records.append(record)
    return records


def _parse_csv(text: str) -> list[Record]:
    reader: csv.DictReader[str] = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV input must include a header row")

    records: list[Record] = []
    for row in reader:
        record: Record = {}
        for key, value in row.items():
            if key:
                record[key] = value
        records.append(record)
    return records


def _canonicalize_record(record: Record) -> Record:
    canonical: Record = {}

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


def _parse_addresses(record: Record) -> list[DnsHostAddress]:
    addresses_raw = record.get("addresses")
    if isinstance(addresses_raw, list):
        addresses: list[DnsHostAddress] = []
        for item in cast(list[object], addresses_raw):
            normalized_item = _normalize_record(item)
            if normalized_item is None:
                continue
            normalized = _canonicalize_address(normalized_item)
            if normalized:
                addresses.append(DnsHostAddress.model_validate(normalized))
        return addresses

    normalized = _canonicalize_address(record)
    if normalized:
        return [DnsHostAddress.model_validate(normalized)]
    return []


def _canonicalize_address(record: Record) -> Record:
    canonical: Record = {}

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


def _pick(source: Record, keys: list[str]) -> object | None:
    for key in keys:
        if key in source:
            return source[key]
    return None


def _parse_optional_int(value: object | None) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if text == "":
        return None
    return int(text)


def _parse_optional_bool(value: object | None) -> bool | None:
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


def _parse_optional_publish(value: object | None) -> str | None:
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


def _normalize_record(value: object) -> Record | None:
    if not isinstance(value, dict):
        return None

    normalized: Record = {}
    for key, item in cast(dict[object, object], value).items():
        if not isinstance(key, str):
            return None
        normalized[key] = item
    return normalized
