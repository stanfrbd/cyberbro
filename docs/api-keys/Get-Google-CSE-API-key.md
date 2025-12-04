Google Custom Search Engine (CSE) will help you to get Google results for Cyberbro analysis.

1. Visit [Programmable Search Engine page](https://developers.google.com/custom-search/v1/overview)
2. Click on "Get a Key" to create or use an existing project and enable the Custom Search API.
3. Copy the API key and the Custom Search Engine ID (CX) from your [CSE control panel](https://programmablesearchengine.google.com/controlpanel/all).

!!! info
    Google Custom Search API has usage limits. The free tier allows for 100 search queries per day. For higher usage, consider enabling billing on your Google Cloud project ($5 per 1000 queries).

You can fill the `secrets.json` accordingly with the variables `"google_cse_key"` and `"google_cse_cx"`, or use the environment variables `GOOGLE_CSE_KEY` and `GOOGLE_CSE_CX` in your custom docker-compose file.