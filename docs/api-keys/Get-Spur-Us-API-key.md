# How to Get Spur.us Token

Spur.us is a paid service that provides various tools and APIs for cybersecurity professionals. Unlike some services, Spur.us does not provide free API keys.  
However, they offer a free access to the website to verify IP addresses. Just like: [https://spur.us/context/1.1.1.1](https://spur.us/context/1.1.1.1) (behind captcha).

## Steps to Retrieve the Spur.us URL

1. **Access the Spur.us Portal:**
    Open your web browser and go to [https://spur.us](https://spur.us).

2. **Log In or Sign Up:**
    Log in with your existing account credentials.  
    If you do not have an account, click "Sign Up" and follow the instructions to create one.

3. **Navigate to the Dashboard:**
    Once logged in, you will be directed to your dashboard. From here, you can access the services provided by Spur.us and get your API key (paid subscription required).

!!! note
    Ensure that you comply with Spur.us's terms of service when using their platform. If you encounter issues, contact their support team for assistance.

Set the `SPUR_US` environment variable in your `.env` file or deployment environment.

!!! warning
    If you don't have API key, only the result URL will be displayed with the note "Unknown - Behind Captcha" in Cyberbro. You'll then have to click on the link and complete the CAPTCHA to access the information. There is no API free tier available.