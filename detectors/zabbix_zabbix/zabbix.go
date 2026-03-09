package zabbixzabbix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

// 定义 JSON-RPC 请求格式
type Request struct {
	Jsonrpc string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      int         `json:"id"`
}

// 定义 JSON-RPC 响应格式
type Response struct {
	Jsonrpc string      `json:"jsonrpc"`
	Result  string      `json:"result"`
	ID      int         `json:"id"`
	Error   interface{} `json:"error,omitempty"`
}

type ZabbixDetector struct {
	httpClient protocols.HTTPClient
}

func NewZabbixDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &ZabbixDetector{httpClient: httpClient}
}

func (d *ZabbixDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果没有前缀协议，自动添加 https
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 解析输入 URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", nil
	}

	// 构造初始URL，移除末尾的 /zabbix 或 zabbix
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host
	baseURL = strings.TrimSuffix(baseURL, "/zabbix")
	baseURL = strings.TrimSuffix(baseURL, "zabbix")

	// 构造完整URL
	targetURL := baseURL + "/zabbix/api_jsonrpc.php"

	// 创建请求数据
	request := Request{
		Jsonrpc: "2.0",
		Method:  "apiinfo.version",
		Params:  []string{},
		ID:      1,
	}

	// 将请求数据转换为 JSON
	jsonData, err := json.Marshal(request)
	if err != nil {
		return "", nil
	}

	// 创建 HTTP 请求配置
	req := protocols.HttpRequest{
		Method:          "POST",
		URL:             targetURL,
		Data:            jsonData,
		Headers:         make(http.Header),
		Timeout:         10 * time.Second,
		ContentType:     "application/json-rpc",
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
	}

	// 发送请求
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", nil
	}

	// 解析响应
	var response Response
	err = json.Unmarshal(resp.Body, &response)
	if err != nil {
		return "", nil
	}

	// 检查错误
	if response.Error != nil {
		return "", nil
	}

	// 返回版本号
	if response.Result != "" {
		return response.Result, nil
	}

	return "", nil
}
