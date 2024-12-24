# DEfO Client Docker Image

This Docker image provides a simple way to use some of the experimental TLS ECH-capable clients.

## Usage

You can fetch the latest image from the GitHub Container Registry using the following command:

```bash
docker pull ghcr.io/defo-project/docker-defo-client:latest
```

The image includes an entrypoint script that you can use to run different commands: `run_command.sh`.

After fetching the image, you can run the container and pass commands as arguments, like this:

### 1. Run Curl

```bash
docker run --rm ghcr.io/defo-project/docker-defo-client:latest curl --doh-url https://1.1.1.1/dns-query --ech true https://test.defo.ie/
```

### 2. Run pyclient

```bash
docker run --rm ghcr.io/defo-project/docker-defo-client:latest pyclient -v get https://defo.ie/ech-check.php
```

Or to fetch a number of test endpoints:

```bash
docker run --rm ghcr.io/defo-project/docker-defo-client:latest pyclient -v getlist --demo
```
