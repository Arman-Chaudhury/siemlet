# Build a fully static siemlet image on scratch.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/siemlet ./cmd/siemlet \
    && mkdir -p /out/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/siemlet /siemlet
COPY --from=build --chown=65534:65534 /out/data /data
COPY configs/rules.example.yaml /etc/siemlet/rules.yaml
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/siemlet"]
CMD ["serve", "--listen", "0.0.0.0:8080", "--rules", "/etc/siemlet/rules.yaml", \
     "--db", "/data/siemlet.db", "--checkpoint-dir", "/data", "/logs/auth.log"]
