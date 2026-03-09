package array_ArrayosAG

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

// ArrayosAGDetector 是版本检测器
type ArrayosAGDetector struct {
	httpClient protocols.HTTPClient
}

// NewArrayosAGDetector 创建一个新的版本检测器
func NewArrayosAGDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &ArrayosAGDetector{httpClient: httpClient}
}

// Detect 检测版本
func (d *ArrayosAGDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果用户输入的目标没有指定协议，默认加上 https
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 拼接访问路径
	url := strings.TrimRight(target, "/") + "/prx/000/http/localhost/login/logout.html"

	// 创建 POST 请求
	req := protocols.HttpRequest{
		Method:          "POST",
		URL:             url,
		Data:            "",
		Headers:         make(http.Header),
		Timeout:         10 * time.Second,
		ContentType:     "application/x-www-form-urlencoded",
		FollowRedirects: true,
	}

	//发送请求获取内容
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Err != nil {
		return "", resp.Err
	}

	// 使用正则表达式提取
	var versionRegex = regexp.MustCompile(`v=([^&"]+)`)
	matches := versionRegex.FindStringSubmatch(string(resp.Body))
	if len(matches) > 1 {
		// 去掉前缀并替换调整格式
		version := strings.TrimPrefix(matches[1], "Rel_AG_")
		version = strings.ReplaceAll(version, "_", ".")
		return version, nil
	}

	return "", nil
}
