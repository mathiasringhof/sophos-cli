# Network - IP Range

## Scope

- Domain: `network`
- Resource: `IPHost` with `HostType=IPRange`
- CLI path: `network ip-range`

## Supported Operations

| CLI Command | Behavior |
| --- | --- |
| `list` | List `IPHost` records with `HostType=IPRange` |
| `get <name>` | Fetch one range object by `Name` |
| `create <name> --start-ip <ip> --end-ip <ip>` | Create an IP range |
| `update <name> --start-ip <ip> --end-ip <ip>` | Update range bounds |
| `delete <name> --yes` | Remove the object |

## SDK Integration

- Read: `get_ip_host()`, `get_ip_host(name=...)`
- Create: `create_ip_range(...)`
- Update: generic `update(xml_tag="IPHost", lookup_key="Name", ...)`
- Delete: generic `remove(xml_tag="IPHost", key="Name")`
