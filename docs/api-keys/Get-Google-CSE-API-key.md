Google Custom Search Engine (CSE) will help you to get Google results for Cyberbro analysis.

1. Visit [Programmable Search Engine page](https://developers.google.com/custom-search/v1/overview)
2. Click on "Get a Key" to create or use an existing project and enable the Custom Search API.
3. Copy the API key and the Custom Search Engine ID (CX) from your [CSE control panel](https://programmablesearchengine.google.com/controlpanel/all).

!!! info
    Google Custom Search API has usage limits. The free tier allows for 100 search queries per day. For higher usage, consider enabling billing on your Google Cloud project ($5 per 1000 queries).

Set `GOOGLE_CSE_KEY` and `GOOGLE_CSE_CX` in your `.env` file or deployment environment.

!!! warning
    Google is discontinuing the Custom Search JSON API on **January 1, 2027** (it is already closed to new customers).
    To keep this engine working, set the optional `GOOGLE_CSE_URL` to any endpoint that implements the same
    Custom Search JSON API (same query parameters and response format), and use that endpoint's key as `GOOGLE_CSE_KEY`.
    If unset, Cyberbro uses Google's default endpoint `https://www.googleapis.com/customsearch/v1`.