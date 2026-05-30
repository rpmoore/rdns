# rdns

## Metrics export note

The current OpenTelemetry OTLP metrics exporter configuration supports plaintext gRPC endpoints.
Use an `http://` endpoint in `OTEL_EXPORTER_OTLP_ENDPOINT`.

HTTPS OTLP endpoints (`https://`) are not currently supported in this configuration.