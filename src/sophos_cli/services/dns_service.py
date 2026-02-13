"""Business logic for DNSHostEntry commands."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

import xmltodict
from sophosfirewall_python.api_client import SophosFirewallZeroRecords

from sophos_cli.firewall_client import FirewallClientProtocol, FirewallObject
from sophos_cli.models.dns import (
    DnsHostAddress,
    DnsHostEntryCreate,
    DnsHostEntryUpdate,
    EntryType,
    IpFamily,
    PublishOnWan,
)


def _new_error_list() -> list[str]:
    return []


@dataclass(slots=True)
class DnsBulkMutationResult:
    """Summary of a bulk add/update operation."""

    total: int
    created: int = 0
    updated: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=_new_error_list)


class DnsService:
    """Service wrapper for managing Sophos DNSHostEntry objects."""

    def __init__(self, client: FirewallClientProtocol):
        self._client = client

    def list_entries(self) -> list[DnsHostEntryCreate]:
        try:
            response = self._client.get_tag(xml_tag="DNSHostEntry")
        except SophosFirewallZeroRecords:
            return []
        return self._parse_entries(response)

    def get_entry(self, host_name: str) -> DnsHostEntryCreate | None:
        try:
            response = self._client.get_tag_with_filter(
                xml_tag="DNSHostEntry",
                key="HostName",
                value=host_name,
                operator="=",
            )
        except SophosFirewallZeroRecords:
            return None

        entries = self._parse_entries(response)
        return entries[0] if entries else None

    def add_entry(
        self, entry: DnsHostEntryCreate, force: bool = False
    ) -> tuple[str, FirewallObject]:
        existing = self.get_entry(entry.host_name)
        if existing and not force:
            raise ValueError(f"DNS entry '{entry.host_name}' already exists")

        if existing:
            response = self._submit_entry(entry, set_operation="update")
            return "updated", response

        response = self._submit_entry(entry, set_operation="add")
        return "created", response

    def update_entry(self, entry: DnsHostEntryUpdate) -> FirewallObject:
        existing = self.get_entry(entry.host_name)
        if not existing:
            raise ValueError(f"DNS entry '{entry.host_name}' does not exist")

        merged = DnsHostEntryCreate(
            host_name=entry.host_name,
            addresses=entry.addresses if entry.addresses is not None else existing.addresses,
            add_reverse_dns_lookup=(
                entry.add_reverse_dns_lookup
                if entry.add_reverse_dns_lookup is not None
                else existing.add_reverse_dns_lookup
            ),
        )

        return self._submit_entry(merged, set_operation="update")

    def add_many(
        self,
        entries: list[DnsHostEntryCreate],
        *,
        force: bool,
        continue_on_error: bool,
    ) -> DnsBulkMutationResult:
        result = DnsBulkMutationResult(total=len(entries))

        for entry in entries:
            try:
                action, _ = self.add_entry(entry, force=force)
                if action == "created":
                    result.created += 1
                else:
                    result.updated += 1
            except Exception as exc:  # pragma: no cover - aggregate command errors
                result.failed += 1
                result.errors.append(f"{entry.host_name}: {exc}")
                if not continue_on_error:
                    break

        return result

    def update_many(
        self,
        entries: list[DnsHostEntryUpdate],
        *,
        continue_on_error: bool,
    ) -> DnsBulkMutationResult:
        result = DnsBulkMutationResult(total=len(entries))

        for entry in entries:
            try:
                self.update_entry(entry)
                result.updated += 1
            except Exception as exc:  # pragma: no cover - aggregate command errors
                result.failed += 1
                result.errors.append(f"{entry.host_name}: {exc}")
                if not continue_on_error:
                    break

        return result

    def _submit_entry(self, entry: DnsHostEntryCreate, set_operation: str) -> FirewallObject:
        payload: FirewallObject = {"DNSHostEntry": self._entry_to_payload(entry)}
        xml_body = xmltodict.unparse(payload, full_document=False)
        response = self._client.submit_xml(template_data=xml_body, set_operation=set_operation)
        return self._normalize_object_dict(response)

    @staticmethod
    def _entry_to_payload(entry: DnsHostEntryCreate) -> FirewallObject:
        address_items = [DnsService._address_to_payload(address) for address in entry.addresses]
        return {
            "HostName": entry.host_name,
            "AddressList": {"Address": address_items},
            "AddReverseDNSLookUp": "Enable" if entry.add_reverse_dns_lookup else "Disable",
        }

    @staticmethod
    def _address_to_payload(address: DnsHostAddress) -> FirewallObject:
        return {
            "EntryType": address.entry_type,
            "IPFamily": address.ip_family,
            "IPAddress": address.ip_address,
            "TTL": str(address.ttl),
            "Weight": str(address.weight),
            "PublishOnWAN": address.publish_on_wan,
        }

    @staticmethod
    def _parse_entries(response: object) -> list[DnsHostEntryCreate]:
        response_dict = DnsService._normalize_object_dict(response)
        response_body = DnsService._normalize_object_dict(response_dict.get("Response"))

        raw_entries = response_body.get("DNSHostEntry")
        if raw_entries is None:
            return []

        raw_records = (
            cast(list[object], raw_entries) if isinstance(raw_entries, list) else [raw_entries]
        )
        entries: list[DnsHostEntryCreate] = []

        for raw_record in raw_records:
            record = DnsService._normalize_object_dict(raw_record)
            if not record:
                continue

            host_name = DnsService._coerce_non_empty_str(record.get("HostName"))
            if host_name is None:
                continue

            addresses = DnsService._parse_addresses(record.get("AddressList"))
            if not addresses:
                continue

            reverse_lookup = DnsService._coerce_reverse_lookup(record.get("AddReverseDNSLookUp"))

            entries.append(
                DnsHostEntryCreate(
                    host_name=host_name,
                    addresses=addresses,
                    add_reverse_dns_lookup=reverse_lookup,
                )
            )

        return entries

    @staticmethod
    def _parse_addresses(address_list_obj: object) -> list[DnsHostAddress]:
        address_list = DnsService._normalize_object_dict(address_list_obj)
        raw_addresses = address_list.get("Address")
        if raw_addresses is None:
            return []

        raw_address_records = (
            cast(list[object], raw_addresses)
            if isinstance(raw_addresses, list)
            else [raw_addresses]
        )
        addresses: list[DnsHostAddress] = []
        for raw_item in raw_address_records:
            item = DnsService._normalize_object_dict(raw_item)
            if not item:
                continue
            try:
                addresses.append(
                    DnsHostAddress(
                        entry_type=DnsService._coerce_entry_type(item.get("EntryType")),
                        ip_family=DnsService._coerce_ip_family(item.get("IPFamily")),
                        ip_address=DnsService._coerce_str(item.get("IPAddress")),
                        ttl=DnsService._coerce_int(item.get("TTL"), default=3600),
                        weight=DnsService._coerce_int(item.get("Weight"), default=0),
                        publish_on_wan=DnsService._coerce_publish_on_wan(item.get("PublishOnWAN")),
                    )
                )
            except ValueError:
                continue
        return addresses

    @staticmethod
    def _coerce_int(value: object | None, default: int) -> int:
        try:
            if value is None or value == "":
                return default
            if isinstance(value, bool):
                return int(value)
            if isinstance(value, int):
                return value
            if isinstance(value, float):
                return int(value)
            if isinstance(value, str):
                return int(value)
            if isinstance(value, (bytes, bytearray)):
                return int(value)
            return default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _coerce_str(value: object | None) -> str:
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _coerce_non_empty_str(value: object | None) -> str | None:
        text = DnsService._coerce_str(value).strip()
        if not text:
            return None
        return text

    @staticmethod
    def _coerce_entry_type(value: object | None) -> EntryType:
        return "InterfaceIP" if DnsService._coerce_str(value).strip() == "InterfaceIP" else "Manual"

    @staticmethod
    def _coerce_ip_family(value: object | None) -> IpFamily:
        return "IPv6" if DnsService._coerce_str(value).strip() == "IPv6" else "IPv4"

    @staticmethod
    def _coerce_publish_on_wan(value: object | None) -> PublishOnWan:
        text = DnsService._coerce_str(value).strip().lower()
        return "Enable" if text == "enable" else "Disable"

    @staticmethod
    def _coerce_reverse_lookup(value: object | None) -> bool:
        return DnsService._coerce_str(value).strip().lower() == "enable"

    @staticmethod
    def _normalize_object_dict(value: object) -> FirewallObject:
        if not isinstance(value, dict):
            return {}

        normalized: FirewallObject = {}
        for key, item in cast(dict[object, object], value).items():
            if isinstance(key, str):
                normalized[key] = item
        return normalized
