package main

import (
	"github.com/origadmin/toolkits/context"
	"github.com/origadmin/toolkits/contrib/metrics/prometheus"
	"github.com/origadmin/toolkits/contrib/middleware/std"
	"github.com/origadmin/toolkits/runtime/service/metrics"
)

func main() {
	cfg := &prometheus.Config{}
	prom := prometheus.WithPrometheus(cfg)
	next := prometheus.Handler(prom)
	mcfg := &metrics.Config{
		Enable:        true,
		ListenPort:    9100,
		UseSecure:     true,
		BasicUserName: "admin",
		BasicPassword: "123456",
	}
	if mcfg.UseSecure {
		mcfg.HandlerFunc = std.BasicAuthHandler(mcfg.BasicUserName, mcfg.BasicPassword, next)
	}
	m, err := metrics.New(mcfg)
	if err != nil {
		panic(err)
	}
	err = m.Start(context.Background())
	if err != nil {
		panic(err)
	}
	defer func() {
		err = m.Stop(context.Background())
		if err != nil {
			panic(err)
		}
	}()
}
