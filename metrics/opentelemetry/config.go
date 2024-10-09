// Copyright (config) 2024 OrigAdmin. All rights reserved.

// Package opentelemetry is the data access object
package opentelemetry

import (
	"net/http"

	"github.com/origadmin/toolkits/metrics"
)

const (
	defaultApplication = "origadmin"
	defaultNamespace   = "backend"
	defaultSubSystem   = "http"
)

var (
	durationBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}
	sizeBuckets     = []float64{100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000}
)

type Config struct {
	Enabled         bool
	LogHandler      map[string]struct{}
	LogMethod       map[string]struct{}
	Application     string
	Namespace       string
	SubSystem       string
	SizeBuckets     []float64
	DurationBuckets []float64
	Objectives      map[float64]float64
	DefaultCollect  bool
	MetricLabels    map[metrics.MetricType][]string
	UseSecure       bool
	BasicUserName   string
	BasicPassword   string
	HandlerFunc     http.HandlerFunc
}

func (c *Config) setup() {
	if c.Application == "" {
		c.Application = defaultApplication
	}

	if c.Namespace == "" {
		c.Namespace = defaultNamespace
	}

	if c.SubSystem == "" {
		c.SubSystem = defaultSubSystem
	}

	if len(c.DurationBuckets) == 0 {
		c.DurationBuckets = durationBuckets
	}

	if len(c.SizeBuckets) == 0 {
		c.SizeBuckets = sizeBuckets
	}

	if len(c.Objectives) == 0 {
		c.Objectives = map[float64]float64{0.9: 0.01, 0.95: 0.005, 0.99: 0.001}
	}

	labels := metrics.MetricLabels()
	for i, l := range c.MetricLabels {
		if len(l) > 0 {
			labels[i] = l
		}
	}
	c.MetricLabels = labels
}
