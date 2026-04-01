FROM golang:1.25.0-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /out/fireslice ./cmd/fireslice
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags='-s -w' -o /out/fireslice-guest-init ./cmd/fireslice-guest-init
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags='-s -w' -o /out/fireslice-guest-ssh ./cmd/fireslice-guest-ssh

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
COPY --from=build /out/fireslice-guest-init /usr/local/bin/fireslice-guest-init
COPY --from=build /out/fireslice-guest-ssh /usr/local/bin/fireslice-guest-ssh

EXPOSE 9090 8083

ENTRYPOINT ["/usr/local/bin/fireslice"]
