package protocols

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// 默认配置值 - 所有变量使用time和http包的标准类型
var (
	defaultHTTPTimeout     = 30 * time.Second   // HTTP请求默认超时时间
	defaultMaxRedirects    = 5                  // 默认最大重定向次数
	defaultContentTypeJSON = "application/json" // 默认内容类型
	defaultMaxRetries      = 2                  // 默认超时重试次数
	defaultRetryDelay      = 1 * time.Second    // 默认重试间隔时间
)

// DefaultHTTPClient 是HTTP客户端的默认实现
type DefaultHTTPClient struct {
	client *http.Client
}

// NewDefaultHTTPClient 创建一个新的默认HTTP客户端
func NewDefaultHTTPClient() HTTPClient {
	return &DefaultHTTPClient{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Do 执行HTTP请求
func (c *DefaultHTTPClient) Do(ctx context.Context, req HttpRequest) (*Response, error) {
	return doHTTP(req)
}

// DoHTTP 执行HTTP请求，支持完整的HTTP功能和超时重试
// 参数：config包含所有HTTP请求相关配置
// 返回：统一的Response结构体和错误信息
func doHTTP(config HttpRequest) (*Response, error) {
	//fix tls: failed to parse certificate from server: x509: negative serial number
	os.Setenv("GODEBUG", "x509negativeserial=1")
	defer os.Unsetenv("GODEBUG")
	// 应用默认配置值
	if config.Timeout == 0 {
		config.Timeout = defaultHTTPTimeout
	}
	if config.MaxRedirects == 0 {
		config.MaxRedirects = defaultMaxRedirects
	}
	if config.ContentType == "" {
		config.ContentType = defaultContentTypeJSON
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = defaultMaxRetries
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = defaultRetryDelay
	}
	var lastError error
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		// 创建HTTP客户端，应用超时设置
		client := &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS10,
					CipherSuites: []uint16{
						tls.TLS_RSA_WITH_RC4_128_SHA,
						tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
						tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_FALLBACK_SCSV,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					},
				},
			},
		}

		// 配置重定向策略
		if !config.FollowRedirects {
			// 禁用重定向
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		} else {
			// 启用重定向并设置最大次数限制
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				if len(via) >= config.MaxRedirects {
					return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
				}
				return nil
			}
		}

		// 处理请求体
		var bodyReader io.Reader
		if config.Data != nil {
			// 根据数据类型进行不同处理
			switch data := config.Data.(type) {
			case string:
				bodyReader = bytes.NewBufferString(data)
			case []byte:
				bodyReader = bytes.NewBuffer(data)
			default:
				// 尝试将任意类型序列化为JSON
				jsonData, err := json.Marshal(config.Data)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal request data: %w", err)
				}
				bodyReader = bytes.NewBuffer(jsonData)
			}
		}

		// 创建HTTP请求
		req, err := http.NewRequest(config.Method, config.URL, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// 应用请求头配置
		if config.Headers != nil {
			for key, values := range config.Headers {
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
		}

		// 设置内容类型头
		if bodyReader != nil && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", config.ContentType)
		}

		// 执行请求
		resp, err := client.Do(req)
		if err != nil {
			lastError = err
			// 检查是否为超时错误，且未达到最大重试次数
			if IsTimeoutError(err) && attempt < config.MaxRetries {
				time.Sleep(config.RetryDelay)
				continue
			}
			return nil, fmt.Errorf("request failed after %d attempts: %w", attempt+1, err)
		}
		defer resp.Body.Close() // 确保响应体被关闭，防止资源泄漏
		// 读取响应体
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		// 返回统一的响应结构
		return &Response{
			StatusCode: resp.StatusCode,
			Body:       body,
			Headers:    resp.Header,
		}, nil
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", config.MaxRetries, lastError)
}

// 检查错误是否为超时错误
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	// 检查 net.Error 接口的 Timeout() 方法
	if nerr, ok := err.(net.Error); ok {
		return nerr.Timeout()
	}
	// 检查上下文超时错误
	if err == context.DeadlineExceeded {
		return true
	}
	// 检查错误消息是否包含超时相关文本
	return strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "deadline exceeded")
}
