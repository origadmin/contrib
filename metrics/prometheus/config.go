package prometheus

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/origadmin/toolkits/metrics"
)

const (
	defaultApplication = "origadmin"
	defaultNamespace   = "backend"
	defaultSubSystem   = "http"
	defaultListenPort  = 9100
)

type Config struct {
	LogHandler      map[string]struct{}
	LogMethod       map[string]struct{}
	Application     string
	Namespace       string
	SubSystem       string
	SlowTime        float64
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

func (c *Config) Setup() {
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
		c.DurationBuckets = prometheus.DefBuckets
	}

	if len(c.SizeBuckets) == 0 {
		c.SizeBuckets = prometheus.ExponentialBuckets(100, 10, 8)
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
