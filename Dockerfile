# Build stage
FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/cflog ./cflog.go

# Runtime stage
FROM alpine:3.20

RUN addgroup -S cflog && adduser -S -G cflog -H -s /sbin/nologin cflog

WORKDIR /opt/cflog

COPY --from=build --chown=root:root /out/cflog /opt/cflog/cflog
RUN chmod 0755 /opt/cflog/cflog

COPY --chown=root:root cflog.conf /opt/cflog/cflog.conf

USER cflog

ENTRYPOINT ["/opt/cflog/cflog"]
CMD ["--config", "/opt/cflog/cflog.conf"]
