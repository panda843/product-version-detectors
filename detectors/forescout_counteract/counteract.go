package forescout_counteract

import (
	"context"
	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// CounteractDetector 是版本检测器
type CounteractDetector struct {
	httpClient protocols.HTTPClient
}

// NewCounteractDetector 创建一个新的版本检测器
func NewCounteractDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &CounteractDetector{httpClient: httpClient}
}

// Detect 检测版本
func (d *CounteractDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果用户输入的目标没有指定协议，默认加上 https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 确保目标以 / 结尾以避免部分网站重定向问题
	if !strings.HasSuffix(target, "/") {
		target += "/"
	}

	// 创建 HTTP 请求，跳过 TLS 验证并设置超时
	req := protocols.HttpRequest{
		Method:          "GET",
		URL:             target,
		Data:            nil,
		Headers:         make(http.Header),
		Timeout:         10 * time.Second,
		ContentType:     "application/json",
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
	}

	// 第一次请求获取初始页面
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Err != nil {
		return "", resp.Err
	}

	// 提取重定向URL，使用初始请求的URL作为基URL
	baseURL, err := url.Parse(target)
	if err != nil {
		return "", nil
	}

	redirectURL := getRedirectURL(string(resp.Body), baseURL)
	if redirectURL != "" {
		// 跟随重定向URL请求
		req.URL = redirectURL
		resp, err = d.httpClient.Do(ctx, req)
		if err != nil {
			return "", err
		}
		if resp.Err != nil {
			return "", resp.Err
		}
	}

	// 提取版本信息并输出结果
	version := exTitle(string(resp.Body))
	if version != "" {
		return version, nil
	}
	return "", nil
}

// exTitle 从HTML内容中提取版本信息
// 使用正则表达式匹配"Version X.X"格式的字符串
// 返回匹配到的版本号，如果未找到则返回"title not found"
func exTitle(html string) string {
	re := regexp.MustCompile(`Version\s([\d.]+)`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// getRedirectURL 从HTML内容中检测客户端重定向
// 使用正则表达式匹配<meta http-equiv="Refresh">标签
// 如果找到相对URL，则使用baseURL将其补全为绝对URL
func getRedirectURL(content string, baseURL *url.URL) string {
	// 检测客户端重定向
	re := regexp.MustCompile(`<meta http-equiv="Refresh" content="0;\s*url=(.*?)"`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		url := strings.TrimSpace(matches[1])
		if !strings.HasPrefix(url, "http") {
			// 相对URL，补全为绝对URL
			if !strings.HasPrefix(url, "/") {
				url = "/" + url
			}
			// 使用baseURL动态补全
			url = baseURL.Scheme + "://" + baseURL.Host + url
		}
		return url
	}
	return ""
}
