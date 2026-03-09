package vmware_vcenter

import (
	"context"
	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// VCenterDetector 是版本检测器
type VCenterDetector struct {
	httpClient protocols.HTTPClient
}

// NewVCenterDetector 创建一个新的版本检测器
func NewVCenterDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &VCenterDetector{httpClient: httpClient}
}

// Detect 检测版本
func (d *VCenterDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果用户输入的目标没有指定协议，默认加上 https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 访问路径
	url := strings.TrimRight(target, "/") + "/sdk/vimServiceVersions.xml"

	// 创建 GET 请求，
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

	// 执行请求并接收响应
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Err != nil {
		return "", resp.Err
	}

	// 使用正则表达式匹配版本信息
	var configRegex = regexp.MustCompile(`<version>(\d+\.\d+\.\d+\.\d+)</version>`)
	matches := configRegex.FindStringSubmatch(string(resp.Body))
	if len(matches) > 0 {
		// 提取匹配到的内容，优先取第一个非空匹配组
		version := ""
		if matches[1] != "" {
			version = matches[1]
		} else if matches[2] != "" {
			version = matches[2]
		}
		return version, nil
	}

	return "", nil
}
