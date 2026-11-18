# Microsoft Tenant Check Engine

## Overview

The **Microsoft Tenant Check** engine determines whether a domain or email address is associated with a Microsoft Entra ID (Azure AD) tenant, and checks whether the domain uses Office 365 mail exchange records.

## How it works

1. **OpenID Configuration lookup**: queries `https://login.microsoftonline.com/<domain>/.well-known/openid-configuration`. A 200 response confirms the domain is registered as a Microsoft tenant.
2. **MX record check**: queries Google DNS for the domain's MX records and detects the presence of `mail.protection.outlook.com`, which indicates Office 365 mail.

## Supported observable types

| Type   | Supported |
|--------|-----------|
| FQDN   | ✅        |
| Email  | ✅        |

For email addresses, the domain part is extracted automatically (e.g. `user@contoso.com` → `contoso.com`).

## API key

No API key required. Free to use.

## Result fields

| Field                  | Description                                              |
|------------------------|----------------------------------------------------------|
| `tenant_found`         | `true` if the domain is a Microsoft tenant               |
| `tenant_id`            | The Azure AD tenant GUID (if found)                      |
| `tenant_region_scope`  | Geographic region of the tenant (e.g. `EU`, `NA`)        |
| `mx_records`           | List of MX hostnames for the domain                      |
| `is_office365_mx`      | `true` if Office 365 MX record detected                  |
| `domain`               | The domain that was checked                              |

## Engine name (API)

```
ms_tenant_check
```
