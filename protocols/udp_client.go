package protocols

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

var (
	defaultUDPTimeout = 10 * time.Second // UDP请求默认超时时间
)

// DefaultUDPClient 是UDP客户端的默认实现
type DefaultUDPClient struct {
	timeout time.Duration
}

// NewDefaultUDPClient 创建一个新的默认UDP客户端
func NewDefaultUDPClient() UDPClient {
	return &DefaultUDPClient{timeout: 10 * time.Second}
}

// Do 连接到UDP服务器
func (c *DefaultUDPClient) Do(ctx context.Context, req TURequest) (*Response, error) {
	return doUDP(req)
}

// DoUDP 执行UDP请求，支持无连接的数据报传输和超时重试
// 参数：config包含UDP请求所需配置
// 返回：统一的Response结构体和错误信息
func doUDP(config TURequest) (*Response, error) {
	// 应用默认配置
	if config.Timeout == 0 {
		config.Timeout = defaultUDPTimeout
	}
	if config.ReadBufferSize == 0 {
		config.ReadBufferSize = defaultReadBufferSize
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = defaultMaxRetries
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = defaultRetryDelay
	}

	var lastError error
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		// 建立UDP连接（实际上是创建一个UDP套接字）
		conn, err := net.DialTimeout("udp", config.Address, config.Timeout)
		if err != nil {
			lastError = err
			// 检查是否为超时错误，且未达到最大重试次数
			if IsTimeoutError(err) && attempt < config.MaxRetries {
				time.Sleep(config.RetryDelay)
				continue
			}
			return nil, fmt.Errorf("UDP connection failed after %d attempts: %w", attempt+1, err)
		}
		defer conn.Close() // 确保套接字被关闭

		// 设置读取超时
		if config.Timeout > 0 {
			conn.SetReadDeadline(time.Now().Add(config.Timeout))
		}

		// 发送请求数据
		if config.Data != nil {
			var dataBytes []byte
			// 根据数据类型进行不同处理
			switch data := config.Data.(type) {
			case string:
				dataBytes = []byte(data)
			case []byte:
				dataBytes = data
			default:
				// 尝试将任意类型序列化为JSON
				jsonData, err := json.Marshal(data)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal request data: %w", err)
				}
				dataBytes = jsonData
			}

			// 发送数据
			_, err := conn.Write(dataBytes)
			if err != nil {
				lastError = err
				if IsTimeoutError(err) && attempt < config.MaxRetries {
					time.Sleep(config.RetryDelay)
					continue
				}
				return nil, fmt.Errorf("failed to send data: %w", err)
			}
		}

		// 接收响应
		buffer := make([]byte, config.ReadBufferSize)
		n, err := conn.Read(buffer)

		if err != nil {
			lastError = err
			if IsTimeoutError(err) && attempt < config.MaxRetries {
				time.Sleep(config.RetryDelay)
				continue
			}
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		// 返回响应，注意截取实际读取的字节数
		return &Response{
			Body: buffer[:n],
		}, nil
	}

	return nil, fmt.Errorf("UDP request failed after %d retries: %w", config.MaxRetries, lastError)
}
