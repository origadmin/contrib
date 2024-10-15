// Copyright (config) 2024 OrigAdmin. All rights reserved.

// Package prometheus is a Prometheus metrics wrapper for metrics.
package prometheus

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/origadmin/toolkits/metrics"
)

// Prometheus is a Prometheus wrapper
// counter only statistics count value in prometheus
// requestDurationSeconds statistics bucket,count,sum in prometheus
// summaryLatency statistics count,sum in prometheus
type Prometheus struct {
	config                 *Config
	registry               *prometheus.Registry
	requestsInFlight       *prometheus.GaugeVec
	requestDurationSeconds *prometheus.HistogramVec
	summaryLatency         *prometheus.SummaryVec
	requestTotal           *prometheus.CounterVec
	requestsSlowTotal      *prometheus.CounterVec
	errorsTotal            *prometheus.CounterVec
	responseSize           *prometheus.HistogramVec
	requestSize            *prometheus.HistogramVec
	event                  *prometheus.CounterVec
	siteEvent              *prometheus.CounterVec
}

// register initializes the Prometheus wrapper
func (obj *Prometheus) register() {
	obj.requestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: obj.config.Namespace,
			Subsystem: obj.config.SubSystem,
			Name:      metrics.MetricRequestsTotal.String(),
			Help:      "How many HTTP requests processed, partitioned by status code and HTTP method.",
		},
		obj.config.MetricLabels[metrics.MetricRequestsTotal],
	)
	obj.registry.MustRegister(obj.requestTotal)

	obj.event = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: obj.config.Namespace,
			Subsystem: obj.config.SubSystem,
			Name:      metrics.MetricEvent.String(),
			Help:      "number of module event",
		},
		obj.config.MetricLabels[metrics.MetricEvent],
	)
	obj.registry.MustRegister(obj.event)

	obj.siteEvent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: obj.config.Namespace,
			Subsystem: obj.config.SubSystem,
			Name:      metrics.MetricSiteEvent.String(),
			Help:      "number of module site event",
		},
		obj.config.MetricLabels[metrics.MetricSiteEvent],
	)
	obj.registry.MustRegister(obj.siteEvent)

	obj.errorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: obj.config.Namespace,
			Subsystem: obj.config.SubSystem,
			Name:      metrics.MetricErrorsTotal.String(),
			Help:      "The HTTP request errors counter",
		},
		obj.config.MetricLabels[metrics.MetricErrorsTotal],
	)
	obj.registry.MustRegister(obj.errorsTotal)

	obj.requestsSlowTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: obj.config.Namespace,
			Subsystem: obj.config.SubSystem,
			Name:      metrics.MetricRequestsSlowTotal.String(),
			Help:      "The HTTP request slow counter",
		},
		obj.config.MetricLabels[metrics.MetricRequestsSlowTotal],
	)
	obj.registry.MustRegister(obj.requestsSlowTotal)

	// Request size requestDurationSeconds
	obj.requestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: obj.config.Namespace,
			Subsystem: obj.config.SubSystem,
			Name:      metrics.MetricRequestSizeBytes.String(),
			Help:      "The HTTP request sizes in bytes.",
			Buckets:   obj.config.SizeBuckets,
		},
		obj.config.MetricLabels[metrics.MetricRequestSizeBytes],
	)
	obj.registry.MustRegister(obj.requestSize)

	// Response size requestDurationSeconds
	obj.responseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: obj.config.Namespace,
			Subsystem: obj.config.SubSystem,
			Name:      metrics.MetricResponseSizeBytes.String(),
			Help:      "The HTTP response sizes in bytes.",
			Buckets:   obj.config.SizeBuckets,
		},
		obj.config.MetricLabels[metrics.MetricResponseSizeBytes],
	)
	obj.registry.MustRegister(obj.responseSize)

	// Request Duration Seconds for module latency
	obj.requestDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: obj.config.Namespace,
			Subsystem: obj.config.SubSystem,
			Name:      metrics.MetricRequestDurationSeconds.String(),
			Help:      "The HTTP request latencies in seconds.",
			Buckets:   obj.config.DurationBuckets,
		},
		obj.config.MetricLabels[metrics.MetricRequestDurationSeconds],
	)
	obj.registry.MustRegister(obj.requestDurationSeconds)

	obj.requestsSlowTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: obj.config.Namespace,
			Subsystem: obj.config.SubSystem,
			Name:      metrics.MetricRequestsSlowTotal.String(),
			Help:      "The HTTP request slow counter",
		},
		obj.config.MetricLabels[metrics.MetricRequestsSlowTotal],
	)
	obj.registry.MustRegister(obj.requestsSlowTotal)

	// Summary for module latency
	obj.summaryLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Namespace:  obj.config.Namespace,
			Subsystem:  obj.config.SubSystem,
			Name:       metrics.MetricSummaryLatency.String(),
			Help:       "summaryLatency of module latency",
			Objectives: obj.config.Objectives,
		},
		obj.config.MetricLabels[metrics.MetricSummaryLatency],
	)
	obj.registry.MustRegister(obj.summaryLatency)

	// Gauge for app state
	obj.requestsInFlight = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: obj.config.Namespace,
			Subsystem: obj.config.SubSystem,
			Name:      metrics.MetricRequestsInFlight.String(),
			Help:      "The HTTP requests in flight, partitioned by status code and HTTP method.",
		},
		obj.config.MetricLabels[metrics.MetricRequestsInFlight],
	)
	obj.registry.MustRegister(obj.requestsInFlight)

	// Register default collectors if enabled
	if obj.config.DefaultCollect {
		obj.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		obj.registry.MustRegister(collectors.NewGoCollector())
	}
}

// Observe uses the Prometheus metric collector to observe and record metrics.
//
// This method takes a reporter parameter of type metrics.Reporter interface,
// which is used to report metric data. Through this method, a Prometheus instance
// can receive and process metric information from various sources, enabling
// real-time monitoring and data collection of system or application performance.
//
// The method does not return any value; its primary purpose is to update and maintain
// the internal metric collectors of Prometheus. By calling this method, one can ensure
// that relevant metric data is correctly collected and stored for subsequent analysis and querying.
func (obj *Prometheus) Observe(reporter metrics.Reporter) {
	obj.Log(reporter.Handler(), reporter.Method(), reporter.Code(), float64(reporter.WriteSize()), float64(reporter.ReadSize()), float64(reporter.Latency()))
}

// Log logs the Handler request and its details.
//
// Parameters:
// - code (string): the code of the request.
// - method (string): the HTTP method of the request.
// - handler (string): the name of the handler.
// - sendBytes (float64): the number of bytes sent in the request.
// - recvBytes (float64): the number of bytes received in the request.
// - latency (float64): the latency of the request.
func (obj *Prometheus) Log(code string, method, handler string, sendBytes, recvBytes, latency float64) {
	if len(obj.config.LogMethod) > 0 {
		if _, ok := obj.config.LogMethod[method]; !ok {
			return // ignore
		}
	}
	if len(obj.config.LogHandler) > 0 {
		if _, ok := obj.config.LogHandler[handler]; !ok {
			return // ignore
		}
	}

	obj.RequestTotal("this", handler, method, code)
	obj.ResponseSize("this", handler, method, code, sendBytes)
	obj.RequestSize("this", handler, method, code, recvBytes)
	obj.RequestDurationSeconds("this", handler, method, latency)
	obj.SummaryLatencyLog("this", handler, method, latency)
}

// RequestTotal logs the request with the given module, handler, method, and code.
//
// Parameters:
// - module (string): the name of the module.
// - handler (string): the name of the handler.
// - method (string): the HTTP method of the request.
// - code (string): the code of the request.
func (obj *Prometheus) RequestTotal(module, handler, method, code string) {
	obj.requestTotal.WithLabelValues(obj.config.Application, module, handler, method, code)
}

// RequestSlowTotal logs the request with the given module, handler, method, code and latency.
//
// Parameters:
// - module (string): the name of the module.
// - handler (string): the name of the handler.
// - method (string): the HTTP method of the request.
// - code (string): the code of the request.
// - latency (float64): the latency of the request.
func (obj *Prometheus) RequestSlowTotal(module, handler, method, code string, latency float64) {
	if latency > obj.config.SlowTime {
		obj.requestsSlowTotal.WithLabelValues(obj.config.Application, module, handler, method, code)
	}
}

// ResponseSize logs the byte count for a specific module, Handler, method, and code.
//
// Parameters:
// - module (string): the name of the module.
// - handler (string): the name of the handler.
// - method (string): the HTTP method of the request.
// - code (string): the code of the request.
// - length (float64): the number of bytes sent in the response.
func (obj *Prometheus) ResponseSize(module, handler, method, code string, length float64) {
	if length > 0 {
		obj.responseSize.WithLabelValues(obj.config.Application, module, handler, method, code).Observe(length)
	}
}

// RequestSize logs the byte count for a specific module, Handler, method, and code.
//
// Parameters:
// - module (string): the name of the module.
// - handler (string): the name of the handler.
// - method (string): the HTTP method of the request.
// - code (string): the code of the request.
// - length (float64): the number of bytes received in the request.
func (obj *Prometheus) RequestSize(module, handler, method, code string, length float64) {
	if length > 0 {
		obj.requestSize.WithLabelValues(obj.config.Application, module, handler, method, code).Observe(length)
	}
}

// RequestDurationSeconds logs the latency of a request in seconds for a specific module, Handler, and method.
//
// Parameters:
// - module (string): the name of the module.
// - handler (string): the name of the handler.
// - method (string): the HTTP method of the request.
// - latency (float64): the latency of the request in seconds.
func (obj *Prometheus) RequestDurationSeconds(module, handler, method string, latency float64) {
	if len(obj.config.DurationBuckets) > 0 {
		obj.requestDurationSeconds.WithLabelValues(obj.config.Application, module, handler, method).Observe(latency)
	}
}

// SummaryLatencyLog logs the latency of a summaryLatency module, Handler, and method.
//
// Parameters:
// - module (string): the name of the module.
// - handler (string): the name of the handler.
// - method (string): the HTTP method of the request.
// - latency (float64): the latency of the request.
func (obj *Prometheus) SummaryLatencyLog(module, handler, method string, latency float64) {
	obj.summaryLatency.WithLabelValues(obj.config.Application, module, handler, method).Observe(latency)
}

// ErrorsTotal logs the occurrence of an exception in a module.
//
// Parameters:
// - module (string): the name of the module.
// - handler (string): the name of the handler.
// - method (string): the HTTP method of the request.
// - errors (string): the description of the error.
func (obj *Prometheus) ErrorsTotal(module, handler, method, errors string) {
	obj.errorsTotal.WithLabelValues(obj.config.Application, module, handler, method, errors).Inc()
}

// Event logs an event in a module.
//
// Parameters:
// - module (string): the name of the module.
// - event (string): the name of the event.
func (obj *Prometheus) Event(module, event string) {
	obj.event.WithLabelValues(obj.config.Application, module, event)
}

// SiteEvent logs an event in a module for a specific site.
//
// Parameters:
// - module (string): the name of the module.
// - event (string): the name of the event.
// - site (string): the name of the site.
func (obj *Prometheus) SiteEvent(module, event, site string) {
	obj.event.WithLabelValues(obj.config.Application, module, event, site)
}

// RequestsInFlight logs a state in a module.
//
// Parameters:
// - module (string): the name of the module.
// - state (string): the name of the state.
// - value (float64): the value of the state.
func (obj *Prometheus) RequestsInFlight(module, state string, value float64) {
	obj.requestsInFlight.WithLabelValues(obj.config.Application, module, state).Set(value)
}

// WithPrometheus creates a Prometheus metrics with given config.
//
// Parameters:
// - conf (*Config): the config for the metrics.
func WithPrometheus(conf *Config) *Prometheus {
	conf.Setup()

	// Create Prometheus metrics with given config.
	m := &Prometheus{
		config:   conf,
		registry: prometheus.NewRegistry(),
	}

	m.register()
	return m
}

func Handler(prom *Prometheus) http.Handler {
	return promhttp.InstrumentMetricHandler(
		prom.registry,
		promhttp.HandlerFor(prom.registry, promhttp.HandlerOpts{}))
}
