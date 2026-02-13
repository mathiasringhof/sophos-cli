"""Models for DNS Host Entry operations."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

EntryType = Literal["Manual", "InterfaceIP"]
IpFamily = Literal["IPv4", "IPv6"]
PublishOnWan = Literal["Enable", "Disable"]

_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _normalize_and_validate_host_name(value: str) -> str:
    normalized = value.strip().rstrip(".")
    if not normalized:
        raise ValueError("host_name must not be empty")
    if len(normalized) > 253:
        raise ValueError("host_name must be 253 characters or less")

    labels = normalized.split(".")
    for label in labels:
        if not _HOST_LABEL_RE.match(label):
            raise ValueError(f"Invalid hostname label: {label}")

    return normalized


class DnsHostAddress(BaseModel):
    """A single DNS host address mapping item."""

    entry_type: EntryType = "Manual"
    ip_family: IpFamily = "IPv4"
    ip_address: str = Field(min_length=1)
    ttl: int = Field(default=3600, ge=1, le=604800)
    weight: int = Field(default=0, ge=0, le=255)
    publish_on_wan: PublishOnWan = "Disable"

    @model_validator(mode="after")
    def validate_address(self) -> DnsHostAddress:
        if self.entry_type == "InterfaceIP":
            return self

        try:
            parsed = ipaddress.ip_address(self.ip_address)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {self.ip_address}") from exc

        if self.ip_family == "IPv4" and parsed.version != 4:
            raise ValueError("ip_family=IPv4 requires an IPv4 address")
        if self.ip_family == "IPv6" and parsed.version != 6:
            raise ValueError("ip_family=IPv6 requires an IPv6 address")

        if parsed.is_multicast:
            raise ValueError("Multicast addresses are not supported")
        if parsed.is_reserved:
            raise ValueError("Reserved addresses are not supported")
        if parsed.is_unspecified:
            raise ValueError("Unspecified addresses are not supported")
        if parsed.is_link_local:
            raise ValueError("Link-local addresses are not supported")
        if parsed.version == 4 and parsed == ipaddress.IPv4Address("255.255.255.255"):
            raise ValueError("Broadcast addresses are not supported")

        return self


class DnsHostEntryCreate(BaseModel):
    """Request model for creating a DNSHostEntry."""

    host_name: str = Field(min_length=1, max_length=253)
    addresses: list[DnsHostAddress] = Field(min_length=1, max_length=8)
    add_reverse_dns_lookup: bool = False

    @field_validator("host_name")
    @classmethod
    def validate_host_name(cls, value: str) -> str:
        return _normalize_and_validate_host_name(value)


class DnsHostEntryUpdate(BaseModel):
    """Request model for updating an existing DNSHostEntry."""

    host_name: str = Field(min_length=1, max_length=253)
    addresses: list[DnsHostAddress] | None = Field(default=None, min_length=1, max_length=8)
    add_reverse_dns_lookup: bool | None = None

    @field_validator("host_name")
    @classmethod
    def validate_host_name(cls, value: str) -> str:
        return _normalize_and_validate_host_name(value)

    @model_validator(mode="after")
    def validate_update_fields(self) -> DnsHostEntryUpdate:
        if self.addresses is None and self.add_reverse_dns_lookup is None:
            raise ValueError(
                "At least one of 'addresses' or 'add_reverse_dns_lookup' must be provided"
            )
        return self
