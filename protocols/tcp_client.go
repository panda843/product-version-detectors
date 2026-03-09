package protocols

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// 默认配置值 - 所有变量使用time和http包的标准类型
var (
	defaultTCPTimeout     = 10 * time.Second // TCP请求默认超时时间
	defaultReadBufferSize = 4096             // 默认读取缓冲区大小
)

// DefaultTCPClient 是TCP客户端的默认实现
type DefaultTCPClient struct {
	timeout time.Duration
}

// NewDefaultTCPClient 创建一个新的默认TCP客户端
func NewDefaultTCPClient() TCPClient {
	return &DefaultTCPClient{timeout: 10 * time.Second}
}

// Do 连接到TCP服务器
func (c *DefaultTCPClient) Do(ctx context.Context, req TURequest) (*Response, error) {
	return doTCP(req)
}

// DoTCP 执行TCP请求，支持可靠的字节流传输和超时重试
// 参数：config包含TCP请求所需配置
// 返回：统一的Response结构体和错误信息
func doTCP(config TURequest) (*Response, error) {
	// 应用默认配置
	if config.Timeout == 0 {
		config.Timeout = defaultTCPTimeout
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
		// 建立TCP连接
		conn, err := net.DialTimeout("tcp", config.Address, config.Timeout)
		if err != nil {
			lastError = err
			// 检查是否为超时错误，且未达到最大重试次数
			if IsTimeoutError(err) && attempt < config.MaxRetries {
				time.Sleep(config.RetryDelay)
				continue
			}
			return nil, fmt.Errorf("TCP connection failed after %d attempts: %w", attempt+1, err)
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
					conn.Close()
					return nil, fmt.Errorf("failed to marshal request data: %w", err)
				}
				dataBytes = jsonData
			}

			// 发送数据
			_, err := conn.Write(dataBytes)
			if err != nil {
				conn.Close()
				lastError = err
				if IsTimeoutError(err) && attempt < config.MaxRetries {
					time.Sleep(config.RetryDelay)
					continue
				}
				return nil, fmt.Errorf("failed to send data: %w", err)
			}
		}

		// 设置读取超时
		if config.Timeout > 0 {
			conn.SetReadDeadline(time.Now().Add(config.Timeout))
		}

		// 接收响应
		buffer := make([]byte, config.ReadBufferSize)
		n, err := conn.Read(buffer)
		conn.Close() // 确保连接被关闭

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

	return nil, fmt.Errorf("TCP request failed after %d retries: %w", config.MaxRetries, lastError)
}
