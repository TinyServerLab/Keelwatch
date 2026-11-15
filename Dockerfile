# syntax=docker/dockerfile:1.7
# Multi-arch build: docker buildx build --platform linux/amd64,linux/arm64 -t keelwatch .

ARG GO_VERSION=1.24
# Trivy is pinned on purpose. Bump deliberately after checking the release
# notes, and prefer pinning by digest (aquasec/trivy:0.71.2@sha256:...).
ARG TRIVY_VERSION=0.71.2

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/keelwatch ./cmd/keelwatch \
 && mkdir -p /out/data/tmp

FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="Keelwatch" \
      org.opencontainers.image.description="Self-hosted Docker security posture dashboard" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /out/keelwatch /usr/local/bin/keelwatch
COPY --from=build --chown=65532:65532 /out/data /data
ENV KEELWATCH_DATA=/data \
    KEELWATCH_ADDR=:8080 \
    TMPDIR=/data/tmp
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["/usr/local/bin/keelwatch", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/keelwatch"]
CMD ["serve"]
