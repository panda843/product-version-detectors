package checkpoint_cpsg

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

// GaiaPortalDetector 是版本检测器
type GaiaPortalDetector struct {
	httpClient protocols.HTTPClient
}

// NewGaiaPortalDetector 创建一个新的版本检测器
func NewGaiaPortalDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &GaiaPortalDetector{httpClient: httpClient}
}

// Detect 检测版本
func (d *GaiaPortalDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果用户输入的目标没有指定协议，默认加上 https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 添加访问路径
	url := strings.TrimRight(target, "/") + "/cgi-bin/login.tcl"

	// 创建 HTTP 请求，跳过 TLS 验证并设置超时
	req := protocols.HttpRequest{
		Method:          "GET",
		URL:             url,
		Data:            nil,
		Headers:         make(http.Header),
		Timeout:         10 * time.Second,
		ContentType:     "application/json",
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
	}
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Err != nil {
		return "", resp.Err
	}

	// 提取版本信息的正则表达式
	var versionRegex = regexp.MustCompile(`version='([^']+)'`)
	matches := versionRegex.FindSubmatch(resp.Body)
	if len(matches) == 2 {
		version := string(matches[1]) // 将匹配结果转换为字符串
		return version, nil
	}

	return "", nil
}
