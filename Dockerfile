# alalanet-agent: local signer and stdio MCP server. The agent key is created on first start
# inside the container (~/.config/alalanet/key); mount a volume there to keep it.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/alalanet-agent ./cmd/alalanet-agent

FROM alpine:3.24
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 agent
USER agent
COPY --from=build /out/alalanet-agent /usr/local/bin/alalanet-agent
ENTRYPOINT ["alalanet-agent", "mcp"]
