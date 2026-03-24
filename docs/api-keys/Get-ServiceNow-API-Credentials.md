# Get ServiceNow API Credentials

Cyberbro uses ServiceNow with **username/password** (Basic Auth).

## Prerequisites

- A ServiceNow instance URL (example: `https://instance.service-now.com`)
- A ServiceNow user account allowed to read:
  - `incident`
  - `sn_si_incident`
  - `sn_si_task`
  - `task`
  - `incident_task`
  - `sc_request`
  - `sc_req_item`

## Configure in `secrets.json`

```json
{
  "servicenow_username": "your_username",
  "servicenow_password": "your_password",
  "servicenow_url": "https://instance.service-now.com"
}
```

## Configure via environment variables

```bash
SERVICENOW_USERNAME=your_username
SERVICENOW_PASSWORD=your_password
SERVICENOW_URL=https://instance.service-now.com
```

## Validation tips

- Test from Cyberbro with an observable known to exist (for example an IP present in incidents).
- In case of empty results, validate permissions and domain visibility on your ServiceNow account.
- If authentication fails, verify username/password and any SSO restriction for API access.
