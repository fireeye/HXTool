# HXTool

## Summary
HXTool is a web-based, standalone tool that can be used with Trellix Endpoint Security (HX).

HXTool provides additional features not directly available in the product by leveraging Trellix Endpoint Security (HX)'s rich API.

### Version
4.8-pre

## Installation
To install HXTool:
1. Ensure that you have a working Python installation, see the [Dependencies](#dependencies) section below for version requirements.
2. Unzip the distribution archive; Or, if you have code repository access, fetch the repo and place the files in a directory.
2. Install HXTool's dependencies by running `pip install -r requirements.txt` from your operating system's command shell.
	- On Windows systems, `pip.exe` can be found in the "scripts" folder under your Python installation directory.
3. After installing the dependencies, run `python hxtool.py` from your operating system's command shell and the server will start listening to tcp port 8080 (HTTPS).
	- Alternatively, on Windows, you should be able to double-click on the `hxtool.py` file.
4. Access the web user interface via a browser: https://127.0.0.1:8080 (tested with Google Chrome and Mozilla Firefox)
5. You will need an account on the Endpoint Security (HX) controller that has either the `api_admin` or `api_analyst` role.
6. Don't forget to set the Background Processing credentials under Admin --> HXTool Settings. These credentials are used by the scheduler, and can be the same as what you have logged in with, or a separate set.

### Dependencies
Python 3.6+

Full dependency list available in [requirements.txt](requirements.txt).

Optionally, the [pymongo](https://pypi.org/project/pymongo/) library may be installed for additional database functionality.

### Configuration
Configuration for HXTool is held in the `conf.json` file, documentation is in [README.CONFIG](README.CONFIG).

### Docker
To build a Docker image from the HXTool source, execute the following: 
```bash
docker build --pull -t hxtool:latest .
```

To run HXTool once the image build process is complete, execute the following:
```bash
docker run -p 8080:8080/tcp -d --cap-add=IPC_LOCK --name hxtool hxtool:latest
```
IPC_LOCK is needed for the GNOME keyring daemon. See [README.DOCKER](README.DOCKER)

## Contribution

### Guidelines
None so far

### Who do I talk to?
* [Henrik Olsson](mailto:henrik.olsson@trellix.com)

### Contributors
* [Elazar Broad](mailto:elazar.broad@trellix.com)
* [Matthew Briggs](mailto:matthew.briggs@trellix.com)
* [Martin Holste](mailto:martin.holste@trellix.com)
