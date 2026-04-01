FROM golang:1.25.0-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags='-s -w' -o /out/fireslice-bastion ./cmd/fireslice-bastion

FROM debian:bookworm-slim

COPY --from=build /out/fireslice-bastion /usr/local/bin/fireslice-bastion

EXPOSE 2222 9191

ENTRYPOINT ["/usr/local/bin/fireslice-bastion"]
