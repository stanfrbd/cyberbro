!!! info
    **Requirements:** Microsoft Defender for Endpoint is a paid service, you must have a tenant to get API keys.  
    You will need an Azure **Global Admin** to help you.

To interact with the Microsoft Defender for Endpoint API, you need to obtain the following credentials:

- Tenant ID (`"mde_tenant_id"` in `secrets.json` or `MDE_TENANT_ID` environment variable).
- Client ID (`"mde_client_id"` in `secrets.json` or `MDE_CLIENT_ID` environment variable).
- Client Secret (`"mde_client_secret"` in `secrets.json` or `MDE_CLIENT_SECRET` environment variable).

Additionally, you need to assign the appropriate API permissions to your application to check IP addresses, hashes, domains, and URLs.

## Steps to Obtain API Credentials

### 1. Register an Application in Azure AD
1. Go to the [**Azure Portal**](https://portal.azure.com/).
2. Navigate to [**Entra ID** > **App registrations**](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade).
3. Click **New registration**.
4. Enter a name for your application.
5. Select the supported account types.
6. Click **Register**.

### 2. Obtain Tenant ID and Client ID
1. After registering the application, you will be redirected to the application's overview page.
2. Copy the **Application (client) ID**. This is your Client ID.
3. Copy the **Directory (tenant) ID**. This is your Tenant ID.

### 3. Create a Client Secret
1. In the application's overview page, navigate to **Certificates & secrets**.
2. Under **Client secrets**, click **New client secret**.
3. Add a description and set an expiration period.
4. Click **Add**.
5. Copy the value of the client secret. This is your Client Secret. **Note:** Make sure to copy it now as it will not be shown again.

## Assign API Permissions

### 1. Navigate to API Permissions
1. In the application's overview page, navigate to **API permissions**.
2. Click **Add a permission**.

### 2. Add Microsoft Defender for Endpoint Permissions
1. Select **APIs my organization uses**.
2. Search for **Microsoft Defender for Endpoint**.
3. Select **Application permissions**.
4. Add the following permissions:
    - `File.Read.All`
    - `Ip.Read.All`
    - `Url.Read.All`

!!! note
    Ensure that these permissions are added under the **Application permissions** section, not **Delegated permissions**.
5. Click **Add permissions**.

### 3. Grant Admin Consent
1. After adding the permissions, click **Grant admin consent for [Your Organization]**.
2. Confirm by clicking **Yes**.

## Summary
You now have the Tenant ID, Client ID, and Client Secret required to authenticate with the Microsoft Defender for Endpoint API. Additionally, you have assigned the necessary permissions to check IP addresses, hashes, domains, and URLs.

For more information, consult [the official documentation](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp).
