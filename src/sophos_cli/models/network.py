"""Models for Wave 1 network resource commands."""

from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, field_validator

GroupAction = Literal["add", "remove", "replace"]


class IpHostCreate(BaseModel):
    """Create or replace a single IP host object."""

    name: str = Field(min_length=1)
    ip_address: str = Field(min_length=1)

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        ipaddress.ip_address(value)
        return value


class IpHostUpdate(IpHostCreate):
    """Update an IP host object."""


class IpNetworkCreate(BaseModel):
    """Create or replace a network object."""

    name: str = Field(min_length=1)
    ip_network: str = Field(min_length=1)
    mask: str = Field(min_length=1)

    @field_validator("ip_network")
    @classmethod
    def validate_network_ip(cls, value: str) -> str:
        ipaddress.ip_address(value)
        return value

    @field_validator("mask")
    @classmethod
    def validate_mask(cls, value: str) -> str:
        ipaddress.ip_address(value)
        return value


class IpNetworkUpdate(IpNetworkCreate):
    """Update a network object."""


class IpRangeCreate(BaseModel):
    """Create or replace an IP range object."""

    name: str = Field(min_length=1)
    start_ip: str = Field(min_length=1)
    end_ip: str = Field(min_length=1)

    @field_validator("start_ip", "end_ip")
    @classmethod
    def validate_ips(cls, value: str) -> str:
        ipaddress.ip_address(value)
        return value


class IpRangeUpdate(IpRangeCreate):
    """Update an IP range object."""


class IpHostGroupCreate(BaseModel):
    """Create an IP host group."""

    name: str = Field(min_length=1)
    host_list: list[str] = Field(min_length=1)
    description: str | None = None


class IpHostGroupUpdate(BaseModel):
    """Update an IP host group."""

    name: str = Field(min_length=1)
    host_list: list[str] = Field(min_length=1)
    action: GroupAction = "add"
    description: str | None = None


class FqdnHostCreate(BaseModel):
    """Create an FQDN host object."""

    name: str = Field(min_length=1)
    fqdn: str = Field(min_length=1)
    fqdn_group_list: list[str] = Field(default_factory=list)
    description: str | None = None


class FqdnHostUpdate(FqdnHostCreate):
    """Update an FQDN host object."""


class FqdnHostGroupCreate(BaseModel):
    """Create an FQDN host group."""

    name: str = Field(min_length=1)
    fqdn_host_list: list[str] = Field(min_length=1)
    description: str | None = None


class FqdnHostGroupUpdate(BaseModel):
    """Update an FQDN host group."""

    name: str = Field(min_length=1)
    fqdn_host_list: list[str] = Field(min_length=1)
    action: GroupAction = "add"
    description: str | None = None
