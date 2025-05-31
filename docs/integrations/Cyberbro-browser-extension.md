# Installing Cyberbro Extension

!!! tip
    This extension requires a running instance of Cyberbro. If you do not have Cyberbro installed, check this doc for instructions on how to set it up.

## Get the extension with the stores

<p>
<a href="https://addons.mozilla.org/addon/cyberbro-analyzer/"><img src="https://user-images.githubusercontent.com/585534/107280546-7b9b2a00-6a26-11eb-8f9f-f95932f4bfec.png" alt="Get Cyberbro Analyzer for Firefox"></a>
<a href="https://chromewebstore.google.com/detail/cyberbro-analyzer/nfcfigpaollodajabegcdobhmgaclbbm"><img src="https://user-images.githubusercontent.com/585534/107280622-91a8ea80-6a26-11eb-8d07-77c548b28665.png" alt="Get Cyberbro Analyzer for Chromium"></a>
<a href="https://microsoftedge.microsoft.com/addons/detail/cyberbro-analyzer/lbponbmcggcepflackehgpbceehagiam"><img src="https://user-images.githubusercontent.com/585534/107280673-a5ece780-6a26-11eb-9cc7-9fa9f9f81180.png" alt="Get Cyberbro Analyzer for Microsoft Edge"></a>
</p>

!!! info
    If you are using a reverse proxy with Cyberbro, ensure that the CORS headers are properly set and that the certificated is trusted on you computer or verified.  
    Without the correct CORS configuration and certificates trust chain (pretty basic, but you can do hardening), the extension will not function correctly.  
    See [the example with Caddy](https://docs.cyberbro.net/integrations/Reverse-Proxy-configuration-%E2%80%90-Caddy/).

For localhost:5000 version of Cyberbro (e.g. on your machine with Docker), CORS is already enabled by default in Flask, so no additional configuration is needed.

## Demo

![image](https://github.com/user-attachments/assets/9c7030dd-76b4-4432-899e-753f5d02bdba)

![cyberbro_chrome_ext](https://github.com/user-attachments/assets/38f45c39-1c62-4d65-9710-7ffee52586a1)

## Development

### Prerequisites
- Google Chrome / Microsoft Edge / Firefox browser
- Git

### Steps to Install on Chrome and Edge for development

1. **Clone the Repository**
    ```sh
    git clone https://github.com/stanfrbd/cyberbro-chrome-extension.git
    cd cyberbro-chrome-extension
    ```

2. **Load the Extension in Chrome**
    - Open Chrome and navigate to `chrome://extensions/`.
    - Enable "Developer mode" by toggling the switch in the top right corner.
    - Click on "Load unpacked" and select the `cyberbro-chrome-extension` directory.

3. **Load the Extension in Edge**
    - Open Edge and navigate to `edge://extensions/`.
    - Enable "Developer mode" by toggling the switch in the bottom left corner.
    - Click on "Load unpacked" and select the `cyberbro-chrome-extension` directory.

### Steps to Install on Firefox for development

**Dev mode:**
 
1. **Clone the repository**:
    ```sh
    git clone https://github.com/stanfrbd/cyberbro-firefox-extension.git
    ```
2. **Navigate to the extension directory**:
    ```sh
    cd cyberbro-firefox-extension
    ```
3. **Open Firefox and go to `about:debugging`**:
    - Click on "This Firefox" in the sidebar.
    - Click on "Load Temporary Add-on..."
    - Select the `manifest.json` file from the cloned repository.

The extension should now be installed in development mode and ready for testing.

## Extension options

After installing the extension, you can configure it by clicking on the extension icon in the browser toolbar and selecting "Options".

The extension options include:
- **Cyberbro URL**: The URL of your Cyberbro instance (e.g. `http://127.0.0.1:5000` - default). This URL is used to send requests to Cyberbro API.
- api-prefix (optional): The prefix for the Cyberbro API (e.g. `/api` - default). This prefix is used to send requests to Cyberbro API.
- Selected engines: The list of engines that will be used to search for the selected text. You can enable or disable engines by checking or unchecking the checkboxes.

!!! note
    The extension will not work if the Cyberbro instance is not running or the URL is incorrect. The engines will not work if the Cyberbro instance does not have the secrets file properly configured.

![image](https://github.com/user-attachments/assets/3415e5f6-98af-4dea-82d3-25d257c7b891)

## Usage

To use the extension, select some text on a webpage, right-click, and choose "Analyze with Cyberbro". The extension will send the selected text to Cyberbro, which will search for it using the enabled engines.

See the [dedicated repo for Chrome and Edge](https://github.com/stanfrbd/cyberbro-chrome-extension)
See the [dedicated repo for Firefox](https://github.com/stanfrbd/cyberbro-firefox-extension)

## Privacy

No information is sent somewhere else than your Cyberbro instance (the one you set in "Cyberbro URL" section).

