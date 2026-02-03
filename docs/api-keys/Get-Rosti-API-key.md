Rösti (Repackaged Open Source Threat Intelligence) provides threat intelligence IOC search via its API. Follow these steps to obtain an API key.

1. **Visit the Rösti API portal:**  
    - Go to [https://rosti.bin.re/api](https://rosti.bin.re/api).

2. **Create an account or sign in:**  
    - Register if you do not already have access, then log in.

3. **Generate an API key:**  
    - In the portal, create a new API key/token. Copy the value and store it securely.

4. **Add the key to Cyberbro:**  
    - Update `secrets.json` with the `"rosti_api_key"` field, or  
    - Export it as an environment variable `ROSTI_API_KEY`, or  
    - Set it in the `.env` file using `ROSTI_API_KEY=your_key`.  

!!! note
    Keep your Rösti API key confidential. Rotate it immediately if you suspect exposure.
