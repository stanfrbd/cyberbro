1. Create a free account on [VirusTotal](https://www.virustotal.com/).
2. Go to [https://www.virustotal.com/gui/user/username/apikey](https://www.virustotal.com/gui/user/username/apikey) (replace `username` with your actual username).
3. Get your token.

!!! info
    You are limited to 500 queries a day with the free VT API.

You can fill the `secrets.json` accordingly with the variable `virustotal` or the environment variable `VIRUSTOTAL` in your custom docker-compose file.