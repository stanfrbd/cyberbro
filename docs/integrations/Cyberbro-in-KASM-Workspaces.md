# Cyberbro has now a KASM Workspaces version

!!! info
    Kasm Workspaces is a docker container streaming platform for delivering browser-based access to desktops, applications, and web services.  
    Link of Cyberbro KASM version (official image from KASM): [https://hub.docker.com/r/kasmweb/cyberbro](https://hub.docker.com/r/kasmweb/cyberbro)

## Demo

![cyberbro_kasm](https://github.com/user-attachments/assets/c07cf40f-2018-455c-9f37-1c96832e9924)

## Installation

### Images for Cyberbro on DockerHub are built regularly by KASM team (and we thank them for that!)

* Link: [https://hub.docker.com/r/kasmweb/cyberbro](https://hub.docker.com/r/kasmweb/cyberbro)
* See more on: [https://hub.docker.com/u/kasmweb](https://hub.docker.com/u/kasmweb) for the other images provided by KASM team.

### Example of config in the KASM GUI

You can use the tags: 

<img width="239" height="439" alt="image" src="https://github.com/user-attachments/assets/282d8fa2-fe42-4731-9744-708ea37d1830" />

- `1.18.0` and later matching your version.

![image](https://github.com/user-attachments/assets/f6ffb648-e161-4c59-9359-51183b0b0ca0)

## Environment Variables

### Firefox Configuration

* `FIREFOX_APP_ARGS` - Additional arguments to pass to firefox when launched.

### Cyberbro Configuration with optional environment variables

All the environment variables are available in the [Cyberbro documentation](https://docs.cyberbro.net/quick-start/Advanced-options-for-deployment).

> Note: if you set `GUI_ENABLED_ENGINES` to `""` then all engines will be enabled in the GUI.  
> By default (even if the variable is not set or enabled), all **free engines** will be enabled in the GUI.

Refer to [https://docs.cyberbro.net/](https://docs.cyberbro.net/) for more information.

You must edit the config in your KASM Cyberbro Workspace settings to add these environment variables, according to [KASM Workspaces documentation examples](https://kasmweb.com/docs/latest/guide/workspaces.html#examples)

![image](https://github.com/user-attachments/assets/33125248-31e8-4315-a772-e0546a8be659)

