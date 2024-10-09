// Copyright (config) 2024 OrigAdmin. All rights reserved.

// Package opentelemetry is the data access object
package opentelemetry

import (
	"maps"
	"sync/atomic"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/origadmin/toolkits/context"
	"github.com/origadmin/toolkits/errors"
	"github.com/origadmin/toolkits/metrics"
)

// OpenTelemetry is a OpenTelemetry wrapper
// counter only statistics count value in prometheus
// requestDurationSeconds statistics bucket,count,sum in prometheus
// summaryLatency statistics count,sum in prometheus
type OpenTelemetry struct {
	ctx                     context.Context
	enabled                 atomic.Bool
	meter                   metric.Meter
	requestsInFlight        metric.Float64UpDownCounter
	counterSendBytes        metric.Int64Histogram
	counterRecvBytes        metric.Int64Histogram
	requestsDurationSeconds metric.Int64Histogram
	requestsTotal           metric.Int64Counter
	requestsSlowTotal       metric.Int64Counter
	exception               metric.Int64Counter
	event                   metric.Int64Counter
	siteEvent               metric.Int64Counter
	logMethod               map[string]struct{}
	logHandler              map[string]struct{}
}

func (t *OpenTelemetry) Enabled() bool {
	return t.enabled.Load()
}

func (t *OpenTelemetry) Disable() {
	t.enabled.Store(false)
}

func (t *OpenTelemetry) CounterException(module, errors string) {
	t.exception.Add(t.Context(), 1, metric.WithAttributes(
		//attribute.String(metrics.MetricLabelInstance, t.config.Application),
		attribute.String(metrics.MetricLabelModule, module),
		attribute.String(metrics.MetricLabelErrors, errors),
	))
}

func (t *OpenTelemetry) CounterEvent(module, event string) {
	t.event.Add(t.Context(), 1, metric.WithAttributes(
		//attribute.String(metrics.MetricLabelInstance, t.config.Application),
		attribute.String(metrics.MetricLabelModule, module),
		attribute.String(metrics.MetricLabelEvent, event),
	))
}

func (t *OpenTelemetry) CounterSiteEvent(module, event, site string) {
	t.siteEvent.Add(t.Context(), 1, metric.WithAttributes(
		//attribute.String(metrics.MetricLabelInstance, t.config.Application),
		attribute.String(metrics.MetricLabelModule, module),
		attribute.String(metrics.MetricLabelEvent, event),
		attribute.String(metrics.MetricLabelSite, site),
	))
}

// register initializes the OpenTelemetry wrapper
func (t *OpenTelemetry) register() error {
	var err error

	// Requests Total
	t.requestsTotal, err = t.meter.Int64Counter(
		metrics.MetricRequestsTotal.String(),
		metric.WithDescription("How many HTTP requests processed, partitioned by status code and HTTP method."),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		return errors.Wrap(err, "failed to register requestsTotal")
	}

	t.requestsSlowTotal, err = t.meter.Int64Counter(
		metrics.MetricRequestsSlowTotal.String(),
		metric.WithDescription("The HTTP request total number of slow requests."),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		return errors.Wrap(err, "failed to register requestsSlowTotal")
	}

	// Response size requestDurationSeconds
	t.counterSendBytes, err = t.meter.Int64Histogram(
		metrics.MetricCounterSendBytes.String(),
		metric.WithDescription("The HTTP response sizes in bytes."),
		metric.WithUnit("By"),
	)
	if err != nil {
		return errors.Wrap(err, "failed to register counterSendBytes")
	}

	// Request Size requestDurationSeconds
	t.counterRecvBytes, err = t.meter.Int64Histogram(
		metrics.MetricCounterRecvBytes.String(),
		metric.WithDescription("The HTTP request sizes in bytes."),
		metric.WithUnit("By"),
	)
	if err != nil {
		return errors.Wrap(err, "failed to register counterRecvBytes")
	}

	// Requests In Flight
	t.requestsInFlight, err = t.meter.Float64UpDownCounter(
		metrics.MetricRequestsInFlight.String(),
		metric.WithDescription("The HTTP requests in flight, partitioned by status code and HTTP method."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return errors.Wrap(err, "failed to register requestsInFlight")
	}

	t.exception, err = t.meter.Int64Counter(
		metrics.MetricCounterException.String(),
		metric.WithDescription("The HTTP request total number of exceptions."),
		metric.WithUnit("{call}"),
	) //counter only exception
	if err != nil {
		return errors.Wrap(err, "failed to register exception")
	}

	t.event, err = t.meter.Int64Counter(
		metrics.MetricCounterEvent.String(),
		metric.WithDescription("The HTTP request total number of events."),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		return errors.Wrap(err, "failed to register event")
	}

	t.siteEvent, err = t.meter.Int64Counter(
		metrics.MetricCounterSiteEvent.String(),
		metric.WithDescription("The HTTP request total number of site events."),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		return errors.Wrap(err, "failed to register siteEvent")
	}

	return nil
}

// Observe uses the OpenTelemetry metric collector to observe and record metrics.
//
// This method takes a reporter parameter of type metrics.Reporter interface,
// which is used to report metric data. Through this method, a OpenTelemetry instance
// can receive and process metric information from various sources, enabling
// real-time monitoring and data collection of system or application performance.
//
// The method does not return any value; its primary purpose is to update and maintain
// the internal metric collectors of OpenTelemetry. By calling this method, one can ensure
// that relevant metric data is correctly collected and stored for subsequent analysis and querying.
func (t *OpenTelemetry) Observe(ctx context.Context, reporter metrics.Report) {
	if !t.Enabled() {
		return
	}
	t.Log(ctx, reporter.Endpoint, reporter.Method, reporter.Code, reporter.SendSize, reporter.RecvSize, reporter.Latency)
}

// Log logs the Handler request and its details.
//
// Parameters: code string, method string, handler string, sendBytes float64, recvBytes float64, latency float64.
func (t *OpenTelemetry) Log(ctx context.Context, code string, method, handler string, sendBytes, recvBytes, latency int64) {
	if !t.Enabled() {
		return
	}
	if len(t.logMethod) > 0 {
		if _, ok := t.logMethod[method]; !ok {
			return // ignore
		}
	}
	if len(t.logHandler) > 0 {
		if _, ok := t.logHandler[handler]; !ok {
			return // ignore
		}
	}

	t.RequestTotal("this", handler, method, code)
	t.CounterSendBytes("this", handler, method, code, sendBytes)
	t.CounterRecvBytes("this", handler, method, code, recvBytes)
	t.RequestsDurationSeconds("this", handler, method, latency)
}

// RequestTotal logs the request with the given module, handler, method, and code.
//
// Parameters: module string, handler string, method string, code string.
// Return type: none.
func (t *OpenTelemetry) RequestTotal(module, handler, method, code string) {
	t.requestsTotal.Add(t.Context(), 1, metric.WithAttributes(
		//attribute.String(metrics.MetricLabelInstance, t.config.Application),
		attribute.String(metrics.MetricLabelModule, module),
		attribute.String(metrics.MetricLabelHandler, handler),
		attribute.String(metrics.MetricLabelMethod, method),
		attribute.String(metrics.MetricLabelCode, code),
	))
}

// CounterSendBytes logs the byte count for a specific module, Handler, method, and code.
//
// Parameters: module string, handler string, method string, code string, length float64.
// Return type: none.
func (t *OpenTelemetry) CounterSendBytes(module, handler, method, code string, length int64) {
	if length > 0 {
		t.counterSendBytes.Record(t.Context(), length, metric.WithAttributes(
			//attribute.String(metrics.MetricLabelInstance, t.config.Application),
			attribute.String(metrics.MetricLabelModule, module),
			attribute.String(metrics.MetricLabelHandler, handler),
			attribute.String(metrics.MetricLabelMethod, method),
			attribute.String(metrics.MetricLabelCode, code),
		))
	}
}

// CounterRecvBytes is a Go function that logs received bytes.
//
// It takes the following parameters: module (string), handler (string), method (string), code (string), length (float64).
// It does not return anything.
func (t *OpenTelemetry) CounterRecvBytes(module, handler, method, code string, length int64) {
	if length > 0 {
		t.counterRecvBytes.Record(t.Context(), length, metric.WithAttributes(
			//attribute.String(metrics.MetricLabelInstance, t.config.Application),
			attribute.String(metrics.MetricLabelModule, module),
			attribute.String(metrics.MetricLabelHandler, handler),
			attribute.String(metrics.MetricLabelMethod, method),
			attribute.String(metrics.MetricLabelCode, code),
		))
	}
}

// RequestsInFlight logs a state in a module.
//
// module: the name of the module.
// state: the name of the state.
// value: the value of the state.
func (t *OpenTelemetry) RequestsInFlight(module, state string, value float64) {
	t.requestsInFlight.Add(t.Context(), value, metric.WithAttributes(
		//attribute.String(metrics.MetricLabelInstance, t.config.Application),
		attribute.String(metrics.MetricLabelModule, module),
		attribute.String(metrics.MetricLabelState, state),
	))
}

// RequestsDurationSeconds logs the latency of a requestDurationSeconds module, Handler, and method.
//
// module: the name of the module.
// handler: the name of the Handler handler.
// method: the name of the method.
// latency: the latency of the Handler call.
func (t *OpenTelemetry) RequestsDurationSeconds(module string, handler string, method string, latency int64) {
	t.requestsDurationSeconds.Record(t.Context(), latency, metric.WithAttributes(
		//attribute.String(metrics.MetricLabelInstance, t.config.Application),
		attribute.String(metrics.MetricLabelModule, module),
		attribute.String(metrics.MetricLabelHandler, handler),
		attribute.String(metrics.MetricLabelMethod, method),
	))
}

func (t *OpenTelemetry) Context() context.Context {
	return t.ctx
}

// New creates a new OpenTelemetry instance with the given configuration.
func New(ctx context.Context, configs ...*Config) (*OpenTelemetry, error) {
	conf := new(Config)
	if len(configs) > 0 {
		conf = configs[0]
	}
	conf.setup()

	m := &OpenTelemetry{
		ctx:        ctx,
		logMethod:  maps.Clone(conf.LogMethod),
		logHandler: maps.Clone(conf.LogHandler),
		meter:      otel.Meter(conf.Application),
	}
	err := m.register()
	if err != nil {
		return nil, err
	}

	return m, nil
}

var _ metrics.Metrics = (*OpenTelemetry)(nil)
