# CLI Support Matrix

This file maps the explicit CLI surface to the current SDK-backed implementation.

## Root Groups

| CLI Group | Status | Notes |
| --- | --- | --- |
| `dns` | Implemented | Explicit CRUD plus bulk create/update and JSON-first output behavior |
| `network` | Implemented | Wave 1 network objects: IP hosts, IP networks, IP ranges, host groups, FQDN hosts, FQDN host groups |
| `raw` | Implemented (hidden) | Fallback escape hatch for unsupported XML tags |
| `service` | Implemented | Explicit CRUD for services, service groups, and URL groups |
| `firewall` | Implemented | Explicit rule, rule-group, and ACL rule commands |
| `zone` | Implemented | Explicit zone CRUD plus interface/VLAN/DNS-forwarder inspection |
| `admin` | Implemented | Explicit admin profile CRUD plus auth/settings inspection |
| `user` | Implemented | Explicit user CRUD plus password update |
| `webfilter` | Implemented | Explicit web filter policy and user activity commands |
| `system` | Implemented | Explicit backup, notification, and retention inspection/update commands |

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
| Service | `service` | `get_service`, `create_service`, `update_service`, `remove` | Service entries are passed with repeated `--entry-json` flags |
| Service group | `service service-group` | `get_service_group`, `create_service_group`, `update_service_group`, `remove` | Membership updates use repeated `--member` flags |
| URL group | `service url-group` | `get_urlgroup`, `create_urlgroup`, `update_urlgroup`, `remove` | Domain updates use repeated `--domain` flags |
| Firewall rule | `firewall rule` | `get_rule`, `create_rule`, `update_rule`, `remove` | Create/update accept JSON rule payloads |
| Firewall rule group | `firewall rule-group` | `get_rulegroup`, `create_rulegroup`, `update_rulegroup`, `remove` | Create/update accept JSON payloads mapped onto SDK kwargs |
| ACL rule | `firewall acl-rule` | `get_acl_rule`, `create_acl_rule`, `update_acl_rule`, `remove` | Create/update accept JSON payloads mapped onto SDK kwargs |
| Zone | `zone` | `get_zone`, `create_zone`, `update_zone`, `remove` | Zone extras are passed as JSON in `zone_params` |
| Interface | `zone interface` | `get_interface` | Read-only inspection |
| VLAN | `zone vlan` | `get_vlan` | Read-only inspection |
| DNS forwarders | `zone dns-forwarders` | `get_dns_forwarders` | Read-only inspection |
| Admin profile | `admin profile` | `get_admin_profile`, `create_admin_profile`, `update_admin_profile`, `remove` | Create/update accept JSON kwargs |
| Admin authentication | `admin authen` | `get_admin_authen` | Read-only inspection |
| Admin settings | `admin settings` | `get_admin_settings` | Read-only inspection |
| Backup | `system backup` | `get_backup`, `update_backup` | Update accepts JSON `backup_params` |
| Notification | `system notification` | `get_notification` | Read-only inspection |
| Notification list | `system notification-list` | `get_notification_list` | Read-only inspection |
| Reports retention | `system reports-retention` | `get_reports_retention` | Read-only inspection |
| User | `user` | `get_user`, `create_user`, `update_user_password`, `remove` | Create accepts JSON kwargs; delete uses `Username` lookup |
| Web filter policy | `webfilter policy` | `get_webfilterpolicy`, `create_webfilterpolicy`, `update_webfilterpolicy`, `remove` | Create/update accept JSON kwargs |
| User activity | `webfilter user-activity` | `get_useractivity`, `create_useractivity`, `remove` | Create accepts JSON kwargs |
