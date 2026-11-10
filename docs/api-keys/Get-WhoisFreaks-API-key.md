# How to Get a WhoisFreaks API Key

The `whoisfreaks` engine uses the WhoisFreaks WHOIS history and reverse WHOIS APIs. It needs an API key.

## Step 1: Create an Account
1. Go to [https://billing.whoisfreaks.com/signup](https://billing.whoisfreaks.com/signup) and create an account.
2. New accounts get 500 one-time credits. No credit card is needed to sign up.

## Step 2: Copy Your API Key
1. Log in at [https://billing.whoisfreaks.com/login](https://billing.whoisfreaks.com/login).
2. Copy the API key shown in your billing dashboard.

## Step 3: Configure Cyberbro
Set the `WHOISFREAKS` environment variable in your `.env` file or deployment environment.

## Credit Usage
- WHOIS history: 2 credits per analyzed domain.
- Reverse WHOIS: 5 credits. The engine only runs it when a past registrant email is found that is not a privacy or redacted address.

## Rate Limits
WhoisFreaks limits requests per minute, and the limit depends on your plan. The engine reads the rate-limit headers on each response and waits for the reset instead of failing. On the smallest plans (1 request per minute), a domain that triggers the reverse WHOIS takes about a minute, and a bulk analysis is spaced out accordingly. Throttled requests do not use credits.

See [WhoisFreaks credit usage](https://whoisfreaks.com/documentation/credit-usage) and [pricing](https://whoisfreaks.com/pricing/api-plans) for current details.
