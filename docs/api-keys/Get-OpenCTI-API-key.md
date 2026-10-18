## How to Get OpenCTI API Key

OpenCTI is an open-source platform that provides a powerful and flexible way to manage cyber threat intelligence. To interact with OpenCTI programmatically, you need an API key. Here is a step-by-step guide on how to obtain an API key from the OpenCTI demo instance.

## Steps to Obtain an API Key for the demo of OpenCTI

1. **Access the Demo Instance (or your instance):**
    Open your web browser and navigate to the OpenCTI demo instance at [https://demo.opencti.io](https://demo.opencti.io).

2. **Log In:**
    If you already have an account, log in using your credentials.  
    If you do not have an account, you will need to register for one.

3. **Navigate to the Settings:**
    Once logged in, click on your profile icon in the top-right corner of the screen and select "Profile" from the dropdown menu.  
    Or go to [https://demo.opencti.io/dashboard/profile/me](https://demo.opencti.io/dashboard/profile/me)

4. **API Keys Section:**
    In the profile page, find and click on the "API" section. This section allows you to manage your API keys.

6. **Copy the API Key:**
    Copy this key and store it securely, as you will need it to authenticate your API requests.

!!! note
    On the demo instance, the key will be regenerated every 24 hours. If you are using OpenCTI in a production environment, you can manage your API keys more securely.

Set `OPENCTI_URL` and `OPENCTI_API_KEY` in your `.env` file or deployment environment.


## Matching behavior

Cyberbro uses equality filters rather than OpenCTI's global full-text search:

- URL lookups intentionally extract the host (including subdomains), ignoring the URL path, port, query and fragment. They do not submit or scan the URL.
- Domains are lowercased, converted to IDNA and stripped of their trailing DNS dot. IP addresses are canonicalized and hashes are lowercased.
- Observable values are matched in their corresponding type and hash algorithm. A description containing an IOC, a parent domain, a different subdomain or a longer IP/hash is not an exact match.
- Exact object names and aliases, canonical simple STIX equality patterns, and indicators explicitly linked to a matching observable are included. Linked indicators do not need to use the IOC as their name.
- Standalone indicators with differently formatted or complex patterns and no observable relationship may not be found. Cyberbro does not interpret arbitrary STIX, Sigma or YARA patterns as IOC matches.

The result count is the number of unique retrieved exact matches and linked indicators; an indicator found through both routes is counted once. The newest indicator is selected by its creation timestamp. Revoked indicators remain visible with their revocation status.

Search results are paginated (100 per page, up to 20 pages). Linked indicators are limited to 100 per observable by the nested API query. If either limit is reached, `results_truncated` is true and the UI warns that counts and the latest indicator only cover the retrieved results. The OpenCTI search link is an investigation pivot into its normal search UI, whose results can be broader than Cyberbro's exact matches.

OpenCTI base URLs with a deployment path, such as `https://cti.example/opencti`, are supported. GraphQL errors, including errors returned with HTTP 200, are reported as engine failures rather than zero matches. A transient connection failure or timeout is retried once.

The GraphQL operations were validated against the official OpenCTI 6.6.0 and current development schemas. Server-side behavior still needs validation on your own OpenCTI deployment before production use.
