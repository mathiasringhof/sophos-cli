"""Service layer for explicit service-domain resources."""

from __future__ import annotations

from sophosfirewall_python.api_client import SophosFirewallZeroRecords

from sophos_cli.command_support import normalize_object_dict, response_records
from sophos_cli.firewall_client import FirewallClientProtocol, FirewallObject
from sophos_cli.models.service import (
    ServiceCreate,
    ServiceGroupCreate,
    ServiceGroupUpdate,
    ServiceUpdate,
    UrlGroupCreate,
    UrlGroupUpdate,
)


class ServiceService:
    """Service wrapper for explicit service commands."""

    def __init__(self, client: FirewallClientProtocol):
        self._client = client

    def list_services(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_service(), "Services")
        except SophosFirewallZeroRecords:
            return []

    def get_service(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_service(name=name), "Services")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def create_service(self, payload: ServiceCreate) -> FirewallObject:
        return normalize_object_dict(
            self._client.create_service(
                name=payload.name,
                service_type=payload.service_type,
                service_list=[entry.model_dump(exclude_none=True) for entry in payload.service_list],
            )
        )

    def update_service(self, payload: ServiceUpdate) -> FirewallObject:
        return normalize_object_dict(
            self._client.update_service(
                name=payload.name,
                service_type=payload.service_type,
                service_list=[entry.model_dump(exclude_none=True) for entry in payload.service_list],
                action=payload.action,
            )
        )

    def delete_service(self, name: str) -> FirewallObject:
        return normalize_object_dict(self._client.remove(xml_tag="Services", name=name, key="Name"))

    def list_service_groups(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_service_group(), "ServiceGroup")
        except SophosFirewallZeroRecords:
            return []

    def get_service_group(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_service_group(name=name), "ServiceGroup")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def create_service_group(self, payload: ServiceGroupCreate) -> FirewallObject:
        return normalize_object_dict(
            self._client.create_service_group(
                name=payload.name,
                service_list=payload.service_list,
                description=payload.description,
            )
        )

    def update_service_group(self, payload: ServiceGroupUpdate) -> FirewallObject:
        return normalize_object_dict(
            self._client.update_service_group(
                name=payload.name,
                service_list=payload.service_list,
                description=payload.description,
                action=payload.action,
            )
        )

    def delete_service_group(self, name: str) -> FirewallObject:
        return normalize_object_dict(self._client.remove(xml_tag="ServiceGroup", name=name, key="Name"))

    def list_url_groups(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_urlgroup(), "WebFilterURLGroup")
        except SophosFirewallZeroRecords:
            return []

    def get_url_group(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_urlgroup(name=name), "WebFilterURLGroup")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def create_url_group(self, payload: UrlGroupCreate) -> FirewallObject:
        return normalize_object_dict(
            self._client.create_urlgroup(name=payload.name, domain_list=payload.domain_list)
        )

    def update_url_group(self, payload: UrlGroupUpdate) -> FirewallObject:
        return normalize_object_dict(
            self._client.update_urlgroup(
                name=payload.name,
                domain_list=payload.domain_list,
                action=payload.action,
            )
        )

    def delete_url_group(self, name: str) -> FirewallObject:
        return normalize_object_dict(
            self._client.remove(xml_tag="WebFilterURLGroup", name=name, key="Name")
        )
