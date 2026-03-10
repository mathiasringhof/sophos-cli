# Network - IP Host Group

## Scope

- Domain: `network`
- Resource: `IPHostGroup`
- CLI path: `network ip-host-group`

## Supported Operations

| CLI Command | Behavior |
| --- | --- |
| `list` | List IP host groups |
| `get <name>` | Fetch one group by `Name` |
| `create <name> --host <member>...` | Create a host group with one or more members |
| `update <name> --host <member>... --action <add|remove|replace>` | Adjust group membership |
| `delete <name> --yes` | Remove the group |

## SDK Integration

- Read: `get_ip_hostgroup()`, `get_ip_hostgroup(name=...)`
- Create: `create_ip_hostgroup(...)`
- Update: `update_ip_hostgroup(...)`
- Delete: generic `remove(xml_tag="IPHostGroup", key="Name")`
