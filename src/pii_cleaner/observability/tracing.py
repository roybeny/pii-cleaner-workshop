"""Opt-in OpenTelemetry bootstrap."""

from __future__ import annotations

from fastapi import FastAPI

from pii_cleaner.config.settings import Settings


def configure_tracing(app: FastAPI, settings: Settings) -> None:
    if not settings.otel_enabled:
        return
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create({"service.name": "pii-cleaner"})
    provider = TracerProvider(resource=resource)
    exporter = (
        OTLPSpanExporter(endpoint=settings.otel_endpoint)
        if settings.otel_endpoint
        else OTLPSpanExporter()
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)
