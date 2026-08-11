!!! info
    **Requirements:** Recorded Future is a paid service that requires a subscription.  
    You must be an **Enterprise Admin** in the platform to create API token.  

1. Log in to [Recorded Future](https://app.recordedfuture.com).
2. Go to [Integration Center > Recorded Future API Integration](https://app.recordedfuture.com/portal/integration-center/detail/recordedfuture-api).
3. Click **Add Instance**.
4. You will be guided to Entreprise Administration.
5. Add a name, click **Continue**.
6. In **Data Access**, select **Threat Intelligence** (you must be subscribed to this service to use it). Cyberbro uses data from the Threat Intelligence product of Recorded Future.
7. Click **Continue**.
8. Copy the generated token - **it will be displayed only once!**

Set the `RECORDED_FUTURE_API_KEY` environment variable in your `.env` file or deployment environment.

!!! info
    For more details, refer to the [official Recorded Future API Access documentation](https://support.recordedfuture.com/hc/en-us/articles/51678132999571-Generate-a-Recorded-Future-API-Token).
