package plixer_scrutinizer

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
)

type PlixerScrutinizerDetector struct {
	httpClient protocols.HTTPClient
}

func NewPlixerScrutinizerDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &PlixerScrutinizerDetector{httpClient: httpClient}
}

func (d *PlixerScrutinizerDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果没有指定协议 默认添加https
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

	// 构造完整URL
	targetURL := baseURL + "/fcgi/scrut_fcgi.fcgi"

	// 创建 HTTP 请求配置
	req := protocols.HttpRequest{
		Method:          "POST",
		URL:             targetURL,
		Data:            "rm=auth&action=initLogin&nosso=0",
		Headers:         http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
		Timeout:         10 * time.Second,
		ContentType:     "application/x-www-form-urlencoded",
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
	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	// 提取版本信息
	re := regexp.MustCompile(`"installedVersion"\s*:\s*"([^"]+)"`)
	matches := re.FindStringSubmatch(string(resp.Body))
	if len(matches) > 1 {
		return getMainVersion(strings.TrimSpace(matches[1])), nil
	}

	return "", nil // 没有找到版本信息
}

// 从完整版本号中提取主要版本部分
func getMainVersion(fullVersion string) string {
	parts := strings.Split(fullVersion, ".")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ".")
	}
	return fullVersion // 如果不足3部分，返回原字符串
}
