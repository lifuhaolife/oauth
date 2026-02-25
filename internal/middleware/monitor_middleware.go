package middleware

import (
	"log"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// APIMetrics API调用统计
type APIMetrics struct {
	mu              sync.RWMutex
	totalRequests   map[string]int64
	totalErrors     map[string]int64
	avgResponseTime map[string]time.Duration
}

var metrics = &APIMetrics{
	totalRequests:   make(map[string]int64),
	totalErrors:     make(map[string]int64),
	avgResponseTime: make(map[string]time.Duration),
}

// MonitorMiddleware API监控中间件
func MonitorMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		
		// 处理请求
		c.Next()
		
		// 记录统计信息
		duration := time.Since(start)
		statusCode := c.Writer.Status()
		
		metrics.mu.Lock()
		defer metrics.mu.Unlock()
		
		// 更新总请求数
		metrics.totalRequests[path]++
		
		// 更新错误数
		if statusCode >= 400 {
			metrics.totalErrors[path]++
		}
		
		// 更新平均响应时间（简单移动平均）
		currentAvg := metrics.avgResponseTime[path]
		if currentAvg == 0 {
			metrics.avgResponseTime[path] = duration
		} else {
			// 简单的移动平均计算
			newAvg := (currentAvg*time.Duration(metrics.totalRequests[path]-1) + duration) / time.Duration(metrics.totalRequests[path])
			metrics.avgResponseTime[path] = newAvg
		}
	}
}

// GetMetrics 获取API统计信息
func GetMetrics() map[string]interface{} {
	metrics.mu.RLock()
	defer metrics.mu.RUnlock()
	
	result := make(map[string]interface{})
	
	for path := range metrics.totalRequests {
		result[path] = map[string]interface{}{
			"total_requests":   metrics.totalRequests[path],
			"total_errors":     metrics.totalErrors[path],
			"success_rate":     100 - float64(metrics.totalErrors[path])*100/float64(metrics.totalRequests[path]),
			"avg_response_ms":  metrics.avgResponseTime[path].Milliseconds(),
		}
	}
	
	return result
}

// MetricsHandler 指标接口处理器
func MetricsHandler(c *gin.Context) {
	c.JSON(200, GetMetrics())
}

// StartMetricsLogger 启动定期日志记录
func StartMetricsLogger() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			metrics.mu.RLock()
			
			log.Println("=== API Metrics Report ===")
			for path, requests := range metrics.totalRequests {
				errors := metrics.totalErrors[path]
				successRate := 100 - float64(errors)*100/float64(requests)
				avgTime := metrics.avgResponseTime[path].Milliseconds()
				
				log.Printf("Path: %s | Requests: %d | Errors: %d | Success Rate: %.2f%% | Avg Time: %dms", 
					path, requests, errors, successRate, avgTime)
			}
			
			metrics.mu.RUnlock()
		}
	}()
}