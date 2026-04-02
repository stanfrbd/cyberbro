!!! info
    **Requirements:** Reversing Labs Spectra Analyze is a paid service that requires a subscription.  
    
    The Spectra Analyze service is also different from the Reversing Labs Spectra Intelligence service. This module only covers the **Spectra Analyze** product.
    You will need an account that has **read-only** permissions to the API to use this service.  
    
    [Reversing Labs Spectra Analyze](https://www.reversinglabs.com/products/spectra-analyze)
    
## Steps to use Reversing Labs Spectra Analyze
1. Create a separate user for this or use your own account in the **Reversing Labs Dashboard**.
2. In the Dashboard, click on the **Help/API docs** to get to the Swagger interface.
3. In the first entry, **Admin**, click on the **Try it out**. Enter  your username and password and choose **Execute**. A token will be returned that is to be used with Cyberbro.
5. Add this value together with the custom URL for Reversing Labs Spectra Analyze in your `.env` file.

Set `RL_ANALYZE_API_KEY` and `RL_ANALYZE_URL` in your `.env` file or deployment environment.

## Support
Documentation for how to create a separate user and/or obtaining an API key is in the [Spectra Analyze officiell documentation](https://docs.reversinglabs.com/SpectraAnalyze/).
It is laid out in detail in [tokens](https://docs.reversinglabs.com/SpectraAnalyze/API%20Documentation/tokens/) for user access and in [Administrator tokens](https://docs.reversinglabs.com/SpectraAnalyze/Administration/#tokens) for administrators.
