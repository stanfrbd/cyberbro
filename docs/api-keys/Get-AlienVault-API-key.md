# How to Get AlienVault OTX API Key

AlienVault OTX (Open Threat Exchange) is a collaborative threat intelligence platform. To interact with OTX programmatically, you need an API key. Follow these steps to obtain your API key from the OTX portal.

## Steps to Obtain an API Key for AlienVault OTX

1. **Access the OTX Portal:**
    Open your web browser and go to [https://otx.alienvault.com](https://otx.alienvault.com).

2. **Log In or Sign Up:**
    Log in with your existing account credentials.  
    If you do not have an account, click "Sign Up" and follow the instructions to create one.

3. **Go to Your Account Settings:**
    Once logged in, click on your username or avatar in the top-right corner and select "Settings" from the dropdown menu.

4. **Find the API Key:**
    In the "API Key" section of your settings page, you will see your personal OTX API key.

5. **Copy the API Key:**
    Copy your API key and store it securely. You will need this key to authenticate your API requests.

!!! note
    Keep your API key confidential. If you believe your key has been compromised, you can regenerate it from the same settings page.

Fill the `secrets.json` file with `"alienvault"`  
or use the environment variable `ALIENVAULT` in your configuration or docker-compose file.