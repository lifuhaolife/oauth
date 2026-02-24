package handler

import (
	"auth-service/internal/model"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

// HealthCheck 健康检查接口
func HealthCheck(c *gin.Context) {
	// 获取系统资源信息
	var cpuPercents []float64
	var memInfo *mem.VirtualMemoryStat
	
	// 异步获取CPU和内存信息，避免阻塞
	done := make(chan struct{})
	go func() {
		cpuPercents, _ = cpu.Percent(time.Second, false)
		memInfo, _ = mem.VirtualMemory()
		close(done)
	}()
	
	select {
	case <-done:
		// 正常获取到信息
	case <-time.After(2 * time.Second):
		// 超时处理
		cpuPercents = []float64{-1}
		memInfo = nil
	}

	response := gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
		"uptime":    time.Now().Unix(), // 简化的运行时间
		"goroutines": runtime.NumGoroutine(),
		"cpu_count":  runtime.NumCPU(),
	}

	// 添加系统资源信息（如果获取成功）
	if len(cpuPercents) > 0 && cpuPercents[0] >= 0 && memInfo != nil {
		response["cpu_usage"] = cpuPercents[0]
		response["memory_total"] = memInfo.Total
		response["memory_used"] = memInfo.Used
		response["memory_usage"] = memInfo.UsedPercent
	}

	model.OK(c, response)
}

// ReadyCheck 就绪检查接口
func ReadyCheck(c *gin.Context) {
	// 检查数据库连接
	db := model.GetDB()
	if db == nil {
		model.FailMsg(c, 50002, "数据库未初始化")
		return
	}

	// 执行简单查询测试
	if err := db.Exec("SELECT 1").Error; err != nil {
		model.FailMsg(c, 50002, "数据库连接异常")
		return
	}

	model.OK(c, gin.H{
		"status":    "ready",
		"timestamp": time.Now().Unix(),
		"database":  "connected",
	})
}