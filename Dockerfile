FROM gcr.io/distroless/base-debian12:nonroot

COPY authprobe /usr/local/bin/authprobe

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/authprobe"]
