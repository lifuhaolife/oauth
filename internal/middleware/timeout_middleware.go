package middleware

import (
	"auth-service/internal/model"
	"context"
	"time"

	"github.com/gin-gonic/gin"
)

// TimeoutMiddleware 请求超时中间件
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 创建带超时的context
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()
		
		// 替换请求的context
		c.Request = c.Request.WithContext(ctx)
		
		// 创建完成通道
		finished := make(chan struct{})
		panicChan := make(chan interface{}, 1)
		
		go func() {
			defer func() {
				if p := recover(); p != nil {
					panicChan <- p
				}
			}()
			
			c.Next()
			finished <- struct{}{}
		}()
		
		select {
		case <-finished:
			// 正常完成
		case <-ctx.Done():
			// 超时处理
			if ctx.Err() == context.DeadlineExceeded {
				model.Fail(c, model.ErrTimeout)
				c.Abort()
			}
		case p := <-panicChan:
			// 恐慌处理
			panic(p)
		}
	}
}