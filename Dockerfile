# Runtime image for denly.
#
# GoReleaser builds the binary on the host and passes it in via the build
# context, so there is no compile stage here. `docker build .` on its own will
# not work — use `goreleaser release --snapshot --clean`, or see
# Dockerfile.local for a self-contained build.
FROM gcr.io/distroless/static-debian12:nonroot

# distroless/static has no shell, no package manager, and no libc to exploit.
# The pure-Go binary needs none of them; it needs only CA certificates, which
# this image already carries for outbound TLS (IPFS pinning, ATProto, Arweave).

COPY denly /usr/local/bin/denly

# /data is the conventional mount point. The image sets DENLY_DATA_DIR so the
# binary does not fall back to a home directory that does not exist here.
ENV DENLY_DATA_DIR=/data \
    DENLY_ADDR=0.0.0.0:8737

# In a container the process is already isolated and must be reachable from
# outside the network namespace, so binding all interfaces is correct here —
# unlike the loopback default for a direct install.

VOLUME ["/data"]
EXPOSE 8737

# nonroot is uid/gid 65532 in distroless. The data volume must be writable by
# it; docker-compose.yml documents this.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/denly"]
CMD ["serve"]
