package gin

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/origadmin/toolkits/metrics"
)

// MetricAdapter is the Gin MetricAdapter.
type MetricAdapter struct {
	reporterPool sync.Pool
	reqKey       string
}

// Middleware is the Gin MetricAdapter function that logs Handler requests and their details.
//
// It takes the following parameters:
// enable: bool, whether to enable the middleware or not.
// reqKey: string, the key to retrieve the received bytes from the context.
func (obj *MetricAdapter) Middleware(metrics metrics.Metrics) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !metrics.Enabled() {
			ctx.Next()
			return
		}
		start := time.Now()
		received := obj.RequestBytes(ctx)
		ctx.Next()
		reporter := obj.Reporter(ctx, start, received)
		metrics.Observe(reporter)
	}
}

// Reporter is the Gin MetricAdapter function that logs Handler requests and their details.
func (obj *MetricAdapter) Reporter(ctx *gin.Context, start time.Time, requestBytes int64) metrics.MetricData {
	// reporter := obj.reporterPool.Get().(*reporter)
	// defer func() {
	// 	obj.reporterPool.Put(reporter)
	// }()
	return metrics.MetricData{
		handler:   obj.Handler(ctx),
		method:    obj.Method(ctx),
		code:      obj.Code(ctx),
		succeed:   ctx.Writer.Status() < 400,
		latency:   time.Since(start).Seconds(),
		writeSize: obj.ResponseBytes(ctx),
		readSize:  requestBytes,
	}
}

func (obj *MetricAdapter) RequestBytes(ctx *gin.Context) int64 {
	if ctx.Request.ContentLength > 0 {
		return ctx.Request.ContentLength
	}
	return 0
}
func (obj *MetricAdapter) ResponseBytes(ctx *gin.Context) int64 {
	return int64(ctx.Writer.Size())
}
func (obj *MetricAdapter) Handler(ctx *gin.Context) string {
	return ctx.FullPath()
}
func (obj *MetricAdapter) Method(ctx *gin.Context) string {
	return ctx.Request.Method
}
func (obj *MetricAdapter) Code(ctx *gin.Context) int {
	return ctx.Writer.Status()
}

// NewMetricsAdapter is the default Gin MetricAdapter.
func NewMetricsAdapter(reqKey string) *MetricAdapter {
	return &MetricAdapter{
		reqKey: reqKey,
		reporterPool: sync.Pool{
			New: func() interface{} {
				return &reporter{}
			},
		},
	}
}
