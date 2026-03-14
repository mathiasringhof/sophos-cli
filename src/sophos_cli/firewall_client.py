"""Typed protocol for firewall client interactions used by services/commands."""

from __future__ import annotations

from typing import Protocol

type FirewallObject = dict[str, object]


class FirewallClientProtocol(Protocol):
    """Subset of SDK methods used by this project."""

    def login(self, output_format: str = "dict") -> object: ...

    def get_tag(
        self,
        xml_tag: str,
        timeout: int = 30,
        output_format: str = "dict",
    ) -> object: ...

    def get_tag_with_filter(
        self,
        xml_tag: str,
        key: str,
        value: str,
        operator: str = "like",
        timeout: int = 30,
        output_format: str = "dict",
    ) -> object: ...

    def submit_xml(
        self,
        template_data: str,
        template_vars: dict[str, object] | None = None,
        set_operation: str = "add",
        timeout: int = 30,
        debug: bool = False,
    ) -> object: ...

    def remove(
        self,
        xml_tag: str,
        name: str,
        key: str = "Name",
        timeout: int = 30,
        output_format: str = "dict",
    ) -> object: ...

    def update(
        self,
        xml_tag: str,
        update_params: dict[str, object],
        name: str | None = None,
        lookup_key: str = "Name",
        output_format: str = "dict",
        timeout: int = 30,
        debug: bool = False,
    ) -> object: ...

    def get_ip_host(
        self,
        name: str | None = None,
        ip_address: str | None = None,
        operator: str = "=",
    ) -> object: ...

    def create_ip_host(
        self,
        name: str,
        ip_address: str | None = None,
        mask: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
        host_type: str = "IP",
        debug: bool = False,
    ) -> object: ...

    def get_ip_hostgroup(self, name: str | None = None, operator: str = "=") -> object: ...

    def create_ip_hostgroup(
        self,
        name: str,
        host_list: list[str],
        description: str | None = None,
        debug: bool = False,
    ) -> object: ...

    def update_ip_hostgroup(
        self,
        name: str,
        host_list: list[str],
        description: str | None = None,
        action: str = "add",
        debug: bool = False,
    ) -> object: ...

    def create_ip_network(
        self,
        name: str,
        ip_network: str,
        mask: str,
        debug: bool = False,
    ) -> object: ...

    def create_ip_range(
        self,
        name: str,
        start_ip: str,
        end_ip: str,
        debug: bool = False,
    ) -> object: ...

    def get_fqdn_host(self, name: str | None = None, operator: str = "=") -> object: ...

    def create_fqdn_host(
        self,
        name: str,
        fqdn: str,
        fqdn_group_list: list[str] | None = None,
        description: str | None = None,
        debug: bool = False,
    ) -> object: ...

    def get_fqdn_hostgroup(self, name: str | None = None, operator: str = "=") -> object: ...

    def create_fqdn_hostgroup(
        self,
        name: str,
        fqdn_host_list: list[str] | None = None,
        description: str | None = None,
        debug: bool = False,
    ) -> object: ...

    def update_fqdn_hostgroup(
        self,
        name: str,
        fqdn_host_list: list[str],
        description: str | None = None,
        action: str = "add",
        debug: bool = False,
    ) -> object: ...

    def get_service(
        self,
        name: str | None = None,
        operator: str = "=",
        dst_proto: str | None = None,
        dst_port: str | None = None,
    ) -> object: ...

    def create_service(
        self,
        name: str,
        service_type: str,
        service_list: list[dict[str, object]],
        debug: bool = False,
    ) -> object: ...

    def update_service(
        self,
        name: str,
        service_type: str,
        service_list: list[dict[str, object]],
        action: str = "add",
        debug: bool = False,
    ) -> object: ...

    def get_service_group(self, name: str | None = None, operator: str = "=") -> object: ...

    def create_service_group(
        self,
        name: str,
        service_list: list[str] | None = None,
        description: str | None = None,
        debug: bool = False,
    ) -> object: ...

    def update_service_group(
        self,
        name: str,
        service_list: list[str],
        description: str | None = None,
        action: str = "add",
        debug: bool = False,
    ) -> object: ...

    def get_urlgroup(self, name: str | None = None, operator: str = "=") -> object: ...

    def create_urlgroup(
        self,
        name: str,
        domain_list: list[str],
        debug: bool = False,
    ) -> object: ...

    def update_urlgroup(
        self,
        name: str,
        domain_list: list[str],
        action: str = "add",
        debug: bool = False,
    ) -> object: ...

    def get_rule(self, name: str | None = None, operator: str = "=") -> object: ...

    def get_rulegroup(self, name: str | None = None, operator: str = "=") -> object: ...

    def get_acl_rule(self, name: str | None = None, operator: str = "=") -> object: ...

    def create_rule(self, rule_params: dict[str, object], debug: bool = False) -> object: ...

    def update_rule(self, name: str, rule_params: dict[str, object], debug: bool = False) -> object: ...

    def create_rulegroup(
        self,
        name: str,
        description: str,
        policy_list: list[object],
        source_zones: list[object],
        dest_zones: list[object],
        policy_type: str,
        debug: bool = False,
    ) -> object: ...

    def update_rulegroup(
        self,
        name: str,
        description: str | None = None,
        policy_list: list[object] | None = None,
        source_zones: list[object] | None = None,
        dest_zones: list[object] | None = None,
        policy_type: str | None = None,
        source_zone_action: str = "add",
        dest_zone_action: str = "add",
        debug: bool = False,
    ) -> object: ...

    def create_acl_rule(self, name: str, debug: bool = False, **kwargs: object) -> object: ...

    def update_acl_rule(self, name: str, debug: bool = False, **kwargs: object) -> object: ...

    def get_zone(self, name: str | None = None, operator: str = "=") -> object: ...

    def create_zone(
        self,
        name: str,
        zone_type: str,
        zone_params: dict[str, object] | None = None,
        debug: bool = False,
    ) -> object: ...

    def update_zone(
        self,
        name: str,
        zone_params: dict[str, object] | None = None,
        debug: bool = False,
    ) -> object: ...

    def get_interface(self, name: str | None = None, operator: str = "=") -> object: ...

    def get_vlan(self, name: str | None = None, operator: str = "=") -> object: ...

    def get_dns_forwarders(self) -> object: ...

    def get_admin_profile(self, name: str | None = None, operator: str = "=") -> object: ...

    def create_admin_profile(self, name: str, debug: bool = False, **kwargs: object) -> object: ...

    def update_admin_profile(self, name: str, debug: bool = False, **kwargs: object) -> object: ...

    def get_admin_authen(self) -> object: ...

    def get_admin_settings(self) -> object: ...

    def get_backup(self, name: str | None = None) -> object: ...

    def update_backup(self, backup_params: dict[str, object], debug: bool = False) -> object: ...

    def get_notification(self, name: str | None = None) -> object: ...

    def get_notification_list(self, name: str | None = None) -> object: ...

    def get_reports_retention(self, name: str | None = None) -> object: ...

    def get_user(self, name: str | None = None, username: str | None = None, operator: str = "=") -> object: ...

    def create_user(self, debug: bool = False, **kwargs: object) -> object: ...

    def update_user_password(self, username: str, new_password: str, debug: bool = False) -> object: ...

    def get_webfilterpolicy(self, name: str | None = None) -> object: ...

    def create_webfilterpolicy(self, name: str, debug: bool = False, **kwargs: object) -> object: ...

    def update_webfilterpolicy(self, name: str, debug: bool = False, **kwargs: object) -> object: ...

    def get_useractivity(self, name: str | None = None) -> object: ...

    def create_useractivity(self, name: str, debug: bool = False, **kwargs: object) -> object: ...
