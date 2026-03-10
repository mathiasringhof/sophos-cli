# Network - IP Network

## Scope

- Domain: `network`
- Resource: `IPHost` with `HostType=Network`
- CLI path: `network ip-network`

## Supported Operations

| CLI Command | Behavior |
| --- | --- |
| `list` | List `IPHost` records with `HostType=Network` |
| `get <name>` | Fetch one network object by `Name` |
| `create <name> --ip-network <ip> --mask <mask>` | Create a network object |
| `update <name> --ip-network <ip> --mask <mask>` | Update address and mask |
| `delete <name> --yes` | Remove the object |

## SDK Integration

- Read: `get_ip_host()`, `get_ip_host(name=...)`
- Create: `create_ip_network(...)`
- Update: generic `update(xml_tag="IPHost", lookup_key="Name", ...)`
- Delete: generic `remove(xml_tag="IPHost", key="Name")`
