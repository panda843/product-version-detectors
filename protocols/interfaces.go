package protocols

import (
	"context"
	"net/http"
	"time"
)

type HttpRequest struct {
	// 基础配置
	Method      string        `json:"method"`                 // 请求方法，如HTTP请求GET、POST、PUT等
	URL         string        `json:"url"`                    // HTTP请求的完整URL
	Data        interface{}   `json:"data,omitempty"`         // 请求数据，可以是字符串、字节切片或可JSON序列化的结构体
	Headers     http.Header   `json:"headers,omitempty"`      // HTTP请求头，用于设置自定义头部信息
	Timeout     time.Duration `json:"timeout,omitempty"`      // 请求超时时间，防止长时间等待无响应的连接
	ContentType string        `json:"content_type,omitempty"` // 请求内容类型，默认值为application/json

	// HTTP专用配置
	FollowRedirects bool `json:"follow_redirects,omitempty"` // 是否自动跟随HTTP重定向
	MaxRedirects    int  `json:"max_redirects,omitempty"`    // 最大重定向次数限制，防止无限重定向

	// 重试配置
	MaxRetries int           `json:"max_retries,omitempty"` // 超时重试次数，默认2次
	RetryDelay time.Duration `json:"retry_delay,omitempty"` // 重试间隔时间，默认1秒
}

type TURequest struct {
	Method  string        `json:"method"`            // 请求方法，TCP/UDP
	Address string        `json:"address"`           // TCP/UDP请求的地址，格式为"host:port"
	Data    interface{}   `json:"data,omitempty"`    // 请求数据，可以是字符串、字节切片或可JSON序列化的结构体
	Timeout time.Duration `json:"timeout,omitempty"` // 请求超时时间，防止长时间等待无响应的连接

	// TCP/UDP专用配置
	ReadBufferSize int `json:"read_buffer_size,omitempty"` // 接收响应数据的缓冲区大小，单位为字节

	// 重试配置
	MaxRetries int           `json:"max_retries,omitempty"` // 超时重试次数，默认2次
	RetryDelay time.Duration `json:"retry_delay,omitempty"` // 重试间隔时间，默认1秒
}

// Response 统一三种请求方式的响应结构
type Response struct {
	StatusCode int         `json:"status_code"` // HTTP状态码，TCP/UDP请求中该值为0
	Body       []byte      `json:"body"`        // 响应体字节数据
	Err        error       `json:"err"`         // 请求过程中发生的错误
	Headers    http.Header `json:"headers"`     // HTTP响应头，TCP/UDP请求中该值为nil
}

// HTTPClient 是HTTP客户端接口
type HTTPClient interface {
	Do(ctx context.Context, req HttpRequest) (*Response, error)
}

// TCPClient 是TCP客户端接口
type TCPClient interface {
	Do(ctx context.Context, req TURequest) (*Response, error)
}

// UDPClient 是UDP客户端接口
type UDPClient interface {
	Do(ctx context.Context, req TURequest) (*Response, error)
}

//// HTTPResponse 是HTTP响应
//type HTTPResponse struct {
//	StatusCode int
//	Headers    map[string][]string
//	Body       []byte
//}

// TCPConnection 是TCP连接接口
//type TCPConnection interface {
//	Send(data []byte) error
//	Receive(timeout time.Duration) ([]byte, error)
//	Close() error
//}

// UDPConnection 是UDP连接接口
//type UDPConnection interface {
//	Send(data []byte) error
//	Receive(timeout time.Duration) ([]byte, error)
//	Close() error
//}
