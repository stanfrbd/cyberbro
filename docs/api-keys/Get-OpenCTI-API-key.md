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

Fill the `secrets.json` file accordingly with `"opencti_url"` and `"opencti_api_key"`  
or use the environment variables `OPENCTI_URL` and `OPENCTI_API_KEY` in your custom docker-compose file.
