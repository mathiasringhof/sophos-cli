# Network - IP Host

## Scope

- Domain: `network`
- Resource: `IPHost`
- CLI path: `network ip-host`

## Supported Operations

| CLI Command | Behavior |
| --- | --- |
| `list` | List IP host objects |
| `get <name>` | Fetch one object by `Name` |
| `create <name> --ip-address <ip>` | Create an `IP` host object |
| `update <name> --ip-address <ip>` | Update the stored IPv4 address |
| `delete <name> --yes` | Remove the object |

## SDK Integration

- Read: `get_ip_host()`, `get_ip_host(name=...)`
- Create: `create_ip_host(name=..., ip_address=..., host_type="IP")`
- Update: generic `update(xml_tag="IPHost", lookup_key="Name", ...)`
- Delete: generic `remove(xml_tag="IPHost", key="Name")`
