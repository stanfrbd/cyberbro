## How to Get MISP API Key

MISP (Malware Information Sharing Platform & Threat Sharing) is an open-source threat intelligence platform. To interact with MISP programmatically, you need an API key. Here is a step-by-step guide on how to obtain an API key from your MISP instance.

## Steps to Obtain an API Key for MISP

1. **Access Your MISP Instance:**
    Open your web browser and navigate to the URL of your MISP instance.

2. **Log In:**
    Enter your credentials to log in to your MISP account.  
    If you do not have an account, contact your MISP administrator to request access.

3. **Navigate to Your Profile:**
    Once logged in, click on your username in the top-right corner and select "My Profile" from the dropdown menu.

4. **Locate the Auth Key:**
    On your profile page, find the "Authkey" section. This is your personal API key for accessing the MISP API.

5. **Copy the API Key:**
    Copy your API key and store it securely. You will need this key to authenticate your API requests.

!!! note
    Keep your API key confidential. If you believe your key has been compromised, you can regenerate it from the same profile page.

Fill the `secrets.json` file with `"misp_url"` and `"misp_api_key"`  
or use the environment variables `MISP_URL` and `MISP_API_KEY` in your configuration or docker-compose file.