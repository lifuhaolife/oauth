// Package httpclient 提供统一的对外 HTTP 客户端。
// 所有对外 HTTP 请求（微信 API、短信服务等）必须通过此包，
// 以保证超时、连接池等参数一致。
package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Default 默认 HTTP 客户端，配置了分层超时控制
var Default = &http.Client{
	Timeout: 30 * time.Second, // 整体请求超时（含重定向）
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second, // TCP 连接建立超时
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,  // TLS 握手超时
		ResponseHeaderTimeout: 10 * time.Second, // 等待响应头超时（防慢响应服务器）
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    false,
	},
}

// DoJSON 发送 JSON 请求，统一处理超时和错误。
// body 为 nil 时发送无请求体的请求（GET 等）。
// 调用方负责关闭返回的 *http.Response.Body。
func DoJSON(ctx context.Context, method, url string, body interface{}) (*http.Response, error) {
	var reqBody *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("httpclient: 序列化请求体失败: %v", err)
		}
		reqBody = bytes.NewBuffer(data)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("httpclient: 创建请求失败: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := Default.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpclient: 请求失败 [%s %s]: %v", method, url, err)
	}

	return resp, nil
}
