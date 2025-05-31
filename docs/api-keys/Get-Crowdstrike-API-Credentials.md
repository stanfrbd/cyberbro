!!! info
    **Requirements:** Crowdstrike is a paid service, you must have an account to get API keys.  
    You will need an account with **administrative permissions** to create API credentials.  
     
    **Falcon Insight XDR** is required to access the API (Device Count).  
    **Falcon Intelligence** or **Falcon Intelligence Premium** is required to access the API (CTI Data).

!!! note
    You can use Cyberbro with **Falcon Insight XDR** only but the CTI data won't be displayed,  
    you will just have Device Count (on how many devices the observable was seen).

To interact with the Crowdstrike API, you need to obtain the following credentials:

- Client ID (`"crowdstrike_client_id"` in `secrets.json` or `CROWDSTRIKE_CLIENT_ID` environment variable).
- Client Secret (`"crowdstrike_client_secret"` in `secrets.json` or `CROWDSTRIKE_CLIENT_SECRET` environment variable).

Additionally, you need to assign the appropriate API permissions to your application to interact with Indicators of Compromise (IOC) and Intel.

## Steps to Obtain API Credentials

### 1. Log in to the Crowdstrike Falcon Console
1. Go to the [**Crowdstrike Falcon Console**](https://falcon.crowdstrike.com/).
2. Log in with your credentials.

### 2. Navigate to API Clients and Keys
1. In the left-hand menu, navigate to [**Support and resources**     **API Clients and Keys**](https://falcon.crowdstrike.com/api-clients-and-keys/clients)
2. Click **Create API client**.

### 3. Create a New API Client
1. Enter a name and description for your API client.
2. Under **Scope**, select the following permissions:
    - IOC Management - Read
    - IOCs (Indicators of Compromise) - Read
    - Indicators (Falcon Intelligence) - Read
    - Actors (Falcon Intelligence) - Read
    - Malware Families (Falcon Intelligence) - Read
    - Reports (Falcon Intelligence) - Read

3. Click **Create**.

### 4. Obtain Client ID and Client Secret
1. After creating the API client, you will be shown the **Client ID** and **Client Secret**.
2. Copy these values and store them securely. 

!!! warning
    Make sure to copy the Client Secret now as it will not be shown again.

## Summary
You now have the Client ID and Client Secret required to authenticate with the Crowdstrike API.  
Additionally, you have assigned the necessary permissions to interact with Indicators of Compromise (IOC) and Intel.

For more information, consult [the official documentation](https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis).

## Configure Falcon URL
!!! tip
    To configure the Falcon link (clickable in the GUI), users may utilize the optional `"crowdstrike_falcon_base_url": "https://falcon.crowdstrike.com"` setting in `secrets.json` or the `CROWDSTRIKE_FALCON_BASE_URL` environment variable.  
    By default, this variable is set to "https://falcon.crowdstrike.com". For instance, those operating within the US2 region should specify the prefix as "https://falcon.us-2.crowdstrike.com".

## Screenshots

![image](https://github.com/user-attachments/assets/e41da79a-065b-4aba-9b73-9c4d25c37bb5)

![image](https://github.com/user-attachments/assets/228ddfe4-c5d6-4d1a-ad50-c086c7e1b2f2)

