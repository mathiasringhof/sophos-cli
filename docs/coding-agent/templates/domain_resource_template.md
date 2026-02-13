# <Domain> - <Resource> (RAW XML API)

## Scope

- Domain: `<dns|dhcp|firewall|...>`
- Resource: `<XMLTag>`
- Supported operations in this CLI: `<Add|Edit|Delete|Get|List>`
- Out of scope: `<anything intentionally excluded>`

## Operation Matrix

| Operation | XML Tag | SDK Call Pattern | Idempotency Strategy |
| --- | --- | --- | --- |
| Add | `<Tag>` | `<client method or generic create>` | `<fail on exists / upsert with force>` |
| Edit | `<Tag>` | `<update>` | `<must exist / create-on-missing>` |

## XML Payload Shape

```xml
<<Tag>>
  <!-- Minimal representative shape -->
</<Tag>>
```

## Field Rules

| Field | Required | Default | Allowed Values / Range | Notes |
| --- | --- | --- | --- | --- |
| `<FieldName>` | `Yes/No` | `<value>` | `<constraints>` | `<details>` |

Include cross-field constraints (for example: "Field B required when Field A = X").

## Validation Rules For CLI Models

- Model name(s): `<Pydantic models>`
- Validation rules to enforce before API call:
  - `<rule 1>`
  - `<rule 2>`

## Status/Response Mapping

| Operation | Code | Meaning | CLI Behavior |
| --- | --- | --- | --- |
| Add | `200` | `<success>` | `<print success + payload>` |
| Add/Edit | `500` | `<validation error>` | `<exit 1 with clear error>` |

Include retry guidance for transient vs non-transient errors.

## SDK Integration Pattern

- Preferred SDK call path:
  - `<primary method>`
  - `<fallback generic method>`
- Response normalization strategy:
  - `<how to parse single vs list payload>`
- Known SDK/API quirks:
  - `<quirk>`

## Examples

### Minimal valid payload

```xml
<!-- minimal example -->
```

### Representative CLI input mapping

```json
{
  "name": "example"
}
```

## Testing Guidance

- Unit tests:
  - `<model validation>`
  - `<service add/update/list parsing>`
- CLI tests:
  - `<success path>`
  - `<error path>`
- Edge cases:
  - `<duplicates>`
  - `<max limits>`

## Open Questions / Unknowns

- `<uncertain behavior to confirm with real firewall>`
