package f5_big_ip_configuration_utility

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

type BigIpDetector struct {
	httpClient protocols.HTTPClient
}

func NewBigIpDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &BigIpDetector{httpClient: httpClient}
}

func (d *BigIpDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果没有前缀协议，自动添加 https
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 解析输入 URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", nil
	}

	// 构造初始URL
	baseURL := parsedURL.Scheme + "://" + parsedURL.Host

	// 首先尝试高版本探测
	targetURL1 := baseURL + "/tmui/tmui/login/expired_password/app/index.html"
	req1 := protocols.HttpRequest{
		Method:          "GET",
		URL:             targetURL1,
		Data:            nil,
		Headers:         make(http.Header),
		Timeout:         5 * time.Second,
		ContentType:     "",
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
	}

	// 发送第一次请求 并匹配结果
	resp1, err := d.httpClient.Do(ctx, req1)
	if err == nil && resp1.StatusCode == http.StatusOK {
		// 提取版本信息
		re := regexp.MustCompile(`<script[^>]*src="app\.js\?ver=([^"]+)"`)
		matches := re.FindStringSubmatch(string(resp1.Body))
		// 匹配到结果直接返回
		if len(matches) >= 2 {
			return getMainVersion(matches[1]), nil
		}
	}

	// 低版本探测
	targetURL2 := baseURL + "/mgmt/tm/sys/version"
	req2 := protocols.HttpRequest{
		Method: "GET",
		URL:    targetURL2,
		Data:   nil,
		Headers: http.Header{
			"Authorization":   []string{"Basic YWRtaW46QVNhc1M="},
			"X-F5-Auth-Token": []string{""},
			"Connection":      []string{"keep-alive, X-F5-Auth-Token"},
		},
		Timeout:         5 * time.Second,
		ContentType:     "application/json",
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
	}

	// 发送第二次请求请求
	resp2, wholeErr := d.httpClient.Do(ctx, req2)
	if wholeErr != nil {
		return "", nil
	}

	// 动态解析 JSON 响应
	var data map[string]interface{}
	if err := json.Unmarshal(resp2.Body, &data); err != nil {
		return "", nil
	}

	// 提取 entries 字段
	entries, ok := data["entries"].(map[string]interface{})
	if !ok {
		return "", nil
	}

	// 遍历响应内容 提取版本
	for _, entry := range entries {
		nestedStats, ok := entry.(map[string]interface{})["nestedStats"]
		if !ok {
			continue
		}
		nestedEntries, ok := nestedStats.(map[string]interface{})["entries"]
		if !ok {
			continue
		}
		// 提取 Version
		version, ok := nestedEntries.(map[string]interface{})["Version"]
		if !ok {
			continue
		}
		versionDesc, ok := version.(map[string]interface{})["description"].(string)
		if !ok {
			continue
		}
		mainVersion := getMainVersion(versionDesc)
		return mainVersion, nil
	}

	return "", nil
}

// 从完整版本号中提取主要版本部分
func getMainVersion(fullVersion string) string {
	parts := strings.Split(fullVersion, ".")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ".")
	}
	return fullVersion // 如果不足3部分，返回原字符串
}
