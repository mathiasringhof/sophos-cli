"""Models for explicit service-domain commands."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

GroupAction = Literal["add", "remove", "replace"]
ServiceType = Literal["TCPorUDP", "IP", "ICMP", "ICMPv6"]


class ServiceEntry(BaseModel):
    """One service definition entry for a service object."""

    protocol: str | None = None
    src_port: str | None = None
    dst_port: str | None = None
    icmp_type: str | None = None
    icmp_code: str | None = None


class ServiceCreate(BaseModel):
    """Create a service object."""

    name: str = Field(min_length=1)
    service_type: ServiceType
    service_list: list[ServiceEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_entries(self) -> "ServiceCreate":
        for entry in self.service_list:
            if self.service_type == "TCPorUDP":
                if not entry.protocol or not entry.dst_port:
                    raise ValueError("TCPorUDP entries require protocol and dst_port.")
            elif self.service_type == "IP":
                if not entry.protocol:
                    raise ValueError("IP entries require protocol.")
            else:
                if entry.icmp_type is None or entry.icmp_code is None:
                    raise ValueError(f"{self.service_type} entries require icmp_type and icmp_code.")
        return self


class ServiceUpdate(ServiceCreate):
    """Update a service object."""

    action: GroupAction = "add"


class ServiceGroupCreate(BaseModel):
    """Create a service group."""

    name: str = Field(min_length=1)
    service_list: list[str] = Field(min_length=1)
    description: str | None = None


class ServiceGroupUpdate(BaseModel):
    """Update a service group."""

    name: str = Field(min_length=1)
    service_list: list[str] = Field(min_length=1)
    action: GroupAction = "add"
    description: str | None = None


class UrlGroupCreate(BaseModel):
    """Create a URL group."""

    name: str = Field(min_length=1)
    domain_list: list[str] = Field(min_length=1)


class UrlGroupUpdate(BaseModel):
    """Update a URL group."""

    name: str = Field(min_length=1)
    domain_list: list[str] = Field(min_length=1)
    action: GroupAction = "add"
