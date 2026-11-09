# syntax=docker/dockerfile:1
# FIX 8: multi-stage build, pinned versions, minimal non-root runtime.

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
# go-sqlite3 needs cgo, so the runtime image keeps glibc (distroless/base).
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/server .

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /data
COPY --from=build /out/server /usr/local/bin/server
USER nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/server", "-healthcheck"]
ENTRYPOINT ["/usr/local/bin/server"]
