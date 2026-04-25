Ransomware.Live provides a Pro API that allows you to search for ransomware victims by domain or name. Follow these steps to obtain an API key.

1. **Visit the Ransomware.Live API portal:**  
    - Go to [https://www.ransomware.live/api](https://www.ransomware.live/api).

2. **Create an account or sign in:**  
    - Register if you do not already have access, then log in.

3. **Generate an API key:**  
    - In the portal, create a new API key. Copy the value and store it securely.

4. **Add the key to Cyberbro:**  
    - Export it as an environment variable `RANSOMWARE_LIVE_API_KEY`, or
    - Set it in the `.env` file using `RANSOMWARE_LIVE_API_KEY=your_key`.

!!! note
    The Pro API is limited to **3,000 calls per day**. Keep your API key confidential and rotate it immediately if you suspect exposure.

## API Reference

- **Base URL:** `https://api-pro.ransomware.live`
- **Search Endpoint:** `GET /victims/search?q=<domain>`
- **Authentication Header:** `X-API-KEY: <your_key>`
- **Documentation:** [https://api-pro.ransomware.live/docs](https://api-pro.ransomware.live/docs)
