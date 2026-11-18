// Protobuf over HTTP: Phoenix rejects the JSON encoding with 415.
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-proto'
import { resourceFromAttributes } from '@opentelemetry/resources'
import { BatchSpanProcessor, NodeTracerProvider } from '@opentelemetry/sdk-trace-node'
import { SpanStatusCode, trace, type Attributes, type Span } from '@opentelemetry/api'

/**
 * Spans cover the security boundaries of a tool call, not every function: one span per
 * call, with a child span for each decision that can stop it.
 */
export const tracer = trace.getTracer('aegis-gateway')

export function initTelemetry(): () => Promise<void> {
  const endpoint = process.env.AEGIS_OTLP_ENDPOINT
  if (!endpoint) {
    process.stderr.write('warning: AEGIS_OTLP_ENDPOINT is unset, traces are not exported\n')
    return async () => {}
  }

  const provider = new NodeTracerProvider({
    resource: resourceFromAttributes({
      'service.name': process.env.AEGIS_SERVICE_NAME ?? 'aegis-gateway',
    }),
    spanProcessors: [new BatchSpanProcessor(new OTLPTraceExporter({ url: endpoint }))],
  })
  provider.register()
  return () => provider.shutdown()
}

/** Runs `fn` inside a child span, recording thrown errors before rethrowing. */
export async function withSpan<T>(
  name: string,
  attributes: Attributes,
  fn: (span: Span) => Promise<T> | T,
): Promise<T> {
  return tracer.startActiveSpan(name, { attributes }, async (span) => {
    try {
      return await fn(span)
    } catch (error) {
      span.recordException(error as Error)
      span.setStatus({ code: SpanStatusCode.ERROR, message: String(error) })
      throw error
    } finally {
      span.end()
    }
  })
}
