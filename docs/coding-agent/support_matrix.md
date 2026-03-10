# CLI Support Matrix

This file maps the explicit CLI surface to the current SDK-backed implementation.

## Root Groups

| CLI Group | Status | Notes |
| --- | --- | --- |
| `dns` | Implemented | Explicit CRUD plus bulk create/update and JSON-first output behavior |
| `network` | Implemented | Wave 1 network objects: IP hosts, IP networks, IP ranges, host groups, FQDN hosts, FQDN host groups |
| `raw` | Implemented (hidden) | Fallback escape hatch for unsupported XML tags |
| `service` | Scaffolded | Reserved for explicit service/service-group/URL-group commands |
| `firewall` | Scaffolded | Reserved for explicit rule/rule-group/ACL commands |
| `zone` | Scaffolded | Reserved for explicit zone/interface/VLAN/DNS-forwarder commands |
| `admin` | Scaffolded | Reserved for admin profiles and settings |
| `user` | Scaffolded | Reserved for firewall user management |
| `webfilter` | Scaffolded | Reserved for web filter policy management |
| `system` | Scaffolded | Reserved for notifications, backups, retention, and related settings |

## Implemented Resource Mapping

| Resource | CLI Path | SDK Methods | Notes |
| --- | --- | --- | --- |
| DNS host entry | `dns` | `get_tag`, `get_tag_with_filter`, `submit_xml`, `remove` | `create`/`create-many` are the primary verbs; legacy `add` aliases remain hidden |
| IP host | `network ip-host` | `get_ip_host`, `create_ip_host`, `update`, `remove` | Explicit single-host object |
| IP network | `network ip-network` | `get_ip_host`, `create_ip_network`, `update`, `remove` | Uses `IPHost` XML objects with `HostType=Network` |
| IP range | `network ip-range` | `get_ip_host`, `create_ip_range`, `update`, `remove` | Uses `IPHost` XML objects with `HostType=IPRange` |
| IP host group | `network ip-host-group` | `get_ip_hostgroup`, `create_ip_hostgroup`, `update_ip_hostgroup`, `remove` | Membership updates use `add/remove/replace` semantics |
| FQDN host | `network fqdn-host` | `get_fqdn_host`, `create_fqdn_host`, `update`, `remove` | Update currently uses generic SDK `update` |
| FQDN host group | `network fqdn-host-group` | `get_fqdn_hostgroup`, `create_fqdn_hostgroup`, `update_fqdn_hostgroup`, `remove` | Membership updates use `add/remove/replace` semantics |
