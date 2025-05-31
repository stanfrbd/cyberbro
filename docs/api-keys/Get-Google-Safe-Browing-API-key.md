1. **Visit Google Cloud Console**: Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. **Create a New Project**: Click on the project dropdown and select "New Project". Name your project and click "Create".
3. **Enable Safe Browsing API**: In the left sidebar, navigate to "APIs & Services" > "Library". Search for "Safe Browsing API" and click on it. Then, click "Enable".
4. **Create Credentials**: Go to "APIs & Services" > "Credentials". Click on "Create Credentials" and select "API Key". Your API key will be generated and displayed.

You can fill the `secrets.json` accordingly with the variable `"google_safe_browsing"` or the environment variable `GOOGLE_SAFE_BROWSING` in your custom docker-compose file.