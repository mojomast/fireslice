FROM golang:1.25.0-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /out/fireslice ./cmd/fireslice

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        docker.io \
        e2fsprogs \
        iproute2 \
        nftables \
        procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/fireslice /usr/local/bin/fireslice

EXPOSE 9090 8083

ENTRYPOINT ["/usr/local/bin/fireslice"]
