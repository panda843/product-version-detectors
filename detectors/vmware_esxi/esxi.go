package vmware_esxi

import (
	"context"
	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// EsxiDetector 是版本检测器
type EsxiDetector struct {
	httpClient protocols.HTTPClient
}

// NewEsxiDetector 创建一个新的版本检测器
func NewEsxiDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &EsxiDetector{httpClient: httpClient}
}

// Detect 检测版本
func (d *EsxiDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果用户输入的目标没有指定协议，默认加上 https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 拼接URL
	url := strings.TrimRight(target, "/") + "/sdk/"

	// 构造SOAP请求体，调用VMware vSphere API的RetrieveServiceContent方法
	// 该方法用于获取VMware ESXi的服务内容，包含版本信息
	xmlData := `<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Header><operationID>esxui-e069</operationID></Header><Body><RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent></Body></Envelope>`

	//创建 POST 请求
	req := protocols.HttpRequest{
		Method:          "POST",
		URL:             url,
		Data:            xmlData,
		Headers:         make(http.Header),
		Timeout:         10 * time.Second,
		ContentType:     "text/xml", // 设置Content-Type头为text/xml，符合SOAP协议要求
		FollowRedirects: true,
		MaxRedirects:    3,
		MaxRetries:      2,
		RetryDelay:      1 * time.Second,
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
	// 匹配格式如：VMware ESXi 7.0.0 build-17630552
	re := regexp.MustCompile(`VMware ESXi (\d+\.\d+\.\d+ build-\d+)`)
	match := re.FindStringSubmatch(string(resp.Body))
	if len(match) > 1 {
		// 输出精确格式，使用原始目标地址和提取到的版本信息
		// match[0]包含整个匹配字符串，match[1]仅包含捕获组中的版本信息
		return getMainVersion(match[1]), nil
	}
	return "", nil
}

// 提取主要版本号
func getMainVersion(versionDesc string) string {
	// 按空格分割字符串
	parts := strings.SplitN(versionDesc, " ", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return versionDesc // 如果无法分割，返回原字符串
}
