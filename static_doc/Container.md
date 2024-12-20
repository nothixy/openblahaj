podman build --tag=openblahaj --no-cache --network host -f Containerfile
podman run --rm --network=host --cap-add=CAP_NET_RAW -it localhost/openblahaj:latest
