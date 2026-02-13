"""Business logic for DNSHostEntry commands."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import xmltodict
from sophosfirewall_python.api_client import SophosFirewallZeroRecords
from sophosfirewall_python.firewallapi import SophosFirewall

from sophos_cli.models.dns import DnsHostAddress, DnsHostEntryCreate, DnsHostEntryUpdate


@dataclass(slots=True)
class DnsBulkMutationResult:
    """Summary of a bulk add/update operation."""

    total: int
    created: int = 0
    updated: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)


class DnsService:
    """Service wrapper for managing Sophos DNSHostEntry objects."""

    def __init__(self, client: SophosFirewall):
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
        self,
        entry: DnsHostEntryCreate,
        force: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        existing = self.get_entry(entry.host_name)
        if existing and not force:
            raise ValueError(f"DNS entry '{entry.host_name}' already exists")

        if existing:
            response = self._submit_entry(entry, set_operation="update")
            return "updated", response

        response = self._submit_entry(entry, set_operation="add")
        return "created", response

    def update_entry(self, entry: DnsHostEntryUpdate) -> dict[str, Any]:
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

    def _submit_entry(self, entry: DnsHostEntryCreate, set_operation: str) -> dict[str, Any]:
        payload = {"DNSHostEntry": self._entry_to_payload(entry)}
        xml_body = xmltodict.unparse(payload, full_document=False)
        return self._client.submit_xml(template_data=xml_body, set_operation=set_operation)

    @staticmethod
    def _entry_to_payload(entry: DnsHostEntryCreate) -> dict[str, Any]:
        address_items = [DnsService._address_to_payload(address) for address in entry.addresses]
        return {
            "HostName": entry.host_name,
            "AddressList": {"Address": address_items},
            "AddReverseDNSLookUp": "Enable" if entry.add_reverse_dns_lookup else "Disable",
        }

    @staticmethod
    def _address_to_payload(address: DnsHostAddress) -> dict[str, Any]:
        return {
            "EntryType": address.entry_type,
            "IPFamily": address.ip_family,
            "IPAddress": address.ip_address,
            "TTL": str(address.ttl),
            "Weight": str(address.weight),
            "PublishOnWAN": address.publish_on_wan,
        }

    @staticmethod
    def _parse_entries(response: dict[str, Any]) -> list[DnsHostEntryCreate]:
        raw = response.get("Response", {}).get("DNSHostEntry")
        if raw is None:
            return []

        records = raw if isinstance(raw, list) else [raw]
        entries: list[DnsHostEntryCreate] = []

        for record in records:
            if not isinstance(record, dict):
                continue
            host_name = record.get("HostName")
            if not host_name:
                continue

            address_list = record.get("AddressList", {})
            addresses_raw = address_list.get("Address") if isinstance(address_list, dict) else None
            if addresses_raw is None:
                continue

            address_records = addresses_raw if isinstance(addresses_raw, list) else [addresses_raw]
            addresses: list[DnsHostAddress] = []

            for item in address_records:
                if not isinstance(item, dict):
                    continue
                try:
                    addresses.append(
                        DnsHostAddress(
                            entry_type=item.get("EntryType", "Manual"),
                            ip_family=item.get("IPFamily", "IPv4"),
                            ip_address=str(item.get("IPAddress", "")),
                            ttl=DnsService._coerce_int(item.get("TTL"), default=3600),
                            weight=DnsService._coerce_int(item.get("Weight"), default=0),
                            publish_on_wan=item.get("PublishOnWAN", "Disable"),
                        )
                    )
                except ValueError:
                    continue

            if not addresses:
                continue

            reverse_lookup = str(record.get("AddReverseDNSLookUp", "Disable")).lower() == "enable"

            entries.append(
                DnsHostEntryCreate(
                    host_name=str(host_name),
                    addresses=addresses,
                    add_reverse_dns_lookup=reverse_lookup,
                )
            )

        return entries

    @staticmethod
    def _coerce_int(value: Any, default: int) -> int:
        try:
            if value is None or value == "":
                return default
            return int(value)
        except (TypeError, ValueError):
            return default
