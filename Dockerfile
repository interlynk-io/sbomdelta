# Use buildx for multi-platform builds
# Build stage
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomdelta"

RUN apk add --no-cache make git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build for multiple architectures
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -a -o sbomdelta .

RUN chmod +x sbomdelta

# Final stage
FROM alpine:3.19
LABEL org.opencontainers.image.source="https://github.com/interlynk-io/sbomdelta"
LABEL org.opencontainers.image.description="sbomdelta is a lightweight CLI tool that explains why vulnerability counts differ between "upstream" & "hardened" images."
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY --from=builder /app/sbomdelta /app/sbomdelta

ENTRYPOINT ["/app/sbomdelta"]
