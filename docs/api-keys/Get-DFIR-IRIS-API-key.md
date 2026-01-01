## How to get a DFIR IRIS API key

[DFIR-IRIS](https://docs.dfir-iris.org/latest/) is an open-source platform for incident response case management and provides a way to manage cases, assets, indicators and timelines.

## Steps to obtain a API key for the demo instance of DFIR-IRIS

1. **Read the Welcome page about how to access the demo instance:**  
   Browse to [DFIR IRIS demo instance](https://v200.beta.dfir-iris.org/welcome) and select an account to use.
   The page show a list of accounts that can be used, and has an **Access Iris** button to get to the demo instance.

2. **Log in**  
   Log in with the account and password selected from the previous step.

3. **Get the API key**  
   Click on the account icon in the top left sidebar and select **Settings**.

4. **Copy the API key**  
   The user settings page will have an API key that can be copied. The key can be renewed and by that disabling any previous key. The key will hold the same permissions as the user.

5. **Optional, create new account**  
   It is possible to log in with an administrator account and then create a new user under the **Advanced/Access Control** tab. Add a new user with a password and assign the user to customers and a role. Then get the API key in the same was as in the previous step.

6. **Optional, use a dedicated service account**  
   To have a dedicated service account that can only do global search, you will first need to add a group with the `search_across_cases` permissions. Create a new group and give it only that permission. When creating a new user, check the `Use as service account` and assign the group to the user.

Fill out the `secrets.json` file accordingly with `"dfir_iris_url"` and `"dfir_iris_api_key"`
or use the environment variables `DFIR_IRIS_URL` and `DFIR_IRIS_API_KEY` in your custom docker-compose file.
