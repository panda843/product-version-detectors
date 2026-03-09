package fortigate

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/detectors/Fortinet/fortigate/mapping"
	"github.com/panda843/product-version-detectors/protocols"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// FortiGateDetector 是版本检测器
type FortiGateDetector struct {
	httpClient protocols.HTTPClient
}

// NewFortiGateDetector 创建一个新的版本检测器
func NewFortiGateDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &FortiGateDetector{httpClient: httpClient}
}

// Detect 检测版本
func (d *FortiGateDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果用户输入的目标没有指定协议，默认加上 https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 创建 Get 请求模板
	req := protocols.HttpRequest{
		Method:          "GET",
		URL:             "",
		Data:            "",
		Headers:         make(http.Header),
		Timeout:         10 * time.Second,
		FollowRedirects: true,
	}

	// 获取静态路径
	staticPath, err := d.GetStaticPath(ctx, req, target)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve static paths")
	}

	// 版本匹配
	matchedKey := ""
	// 1.ver_mod.json 型号匹配
	verModData, err := mapping.LoadEmbeddedJSONData("resources/fortigate_mod_ver.json")
	if err == nil && verModData != nil {
		matchedKey, err = d.MatchVersionAndModel(ctx, req, target, staticPath, verModData)
		if matchedKey == "" {
			// 2.ver_mod.json 未找到匹配或加载失败，尝试访问特定路径
			matchedKey, err = d.MatchSpecificPaths(ctx, req, target, staticPath)
			if matchedKey == "" { // 如果 MatchSpecificPaths 返回错误
				// 3.未在特定路径中找到有效版本或路径无法访问,尝试使用版本文件进行匹配
				verData, _ := mapping.LoadEmbeddedJSONData("resources/fortigate_ver.json")
				if verData != nil {
					matchedKey, err = d.MatchUniqueVersion(ctx, req, target, staticPath, verData)
				}
			}
		}
	}

	// 处理matchedKey，统一版本号格式,示例：7.2.8
	if matchedKey != "" {
		matchedKey = d.formatVersion(matchedKey)
	}

	return matchedKey, nil
}

// 从提供的目标 URL 返回内容中提取静态路径
func (d *FortiGateDetector) GetStaticPath(ctx context.Context, req protocols.HttpRequest, target string) (string, error) {
	// 规范化URL，确保以根目录结尾
	if !strings.HasSuffix(target, "/") {
		target += "/"
	}
	req.URL = target
	//发送请求获取内容
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Err != nil {
		return "", resp.Err
	}

	// 检查状态码
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("target responded with an error status code")
	}

	// 检查 Content-Type 确保是 HTML 或 JavaScript 只处理特定响应
	contentType := resp.Headers.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "javascript") {
		return "", fmt.Errorf("response content type does not meet expectations")
	}

	//查找 login.js 或 legacy_theme_setup.js
	loginJSPathRegex := regexp.MustCompile(`(?:['"]|\b)(?:/|https?://[^/]+/)([a-zA-Z0-9_-]{1,32})/js/(?:login|legacy_theme_setup)(?:\.min)?\.js(?:\?[^'"]*)?(?:['"]|\b)`)
	loginJSMatches := loginJSPathRegex.FindStringSubmatch(string(resp.Body))

	if len(loginJSMatches) > 1 && loginJSMatches[1] != "" {
		extractedPath := loginJSMatches[1]
		return extractedPath, nil
	}

	// 如果未找到脚本，尝试提取 <base href>
	baseHrefRegex := regexp.MustCompile(`<base\s+href\s*=\s*['"](?:/|https?://[^/]+/)?([a-zA-Z0-9_-]{1,32})/?['"]`)
	baseHrefMatches := baseHrefRegex.FindStringSubmatch(string(resp.Body))

	if len(baseHrefMatches) > 1 && baseHrefMatches[1] != "" {
		extractedPath := baseHrefMatches[1]
		return extractedPath, nil
	}

	return "", fmt.Errorf("no valid static paths were found")
}

// 1、使用版本+型号文件进行匹配 找到第一个结果就返回
func (d *FortiGateDetector) MatchVersionAndModel(ctx context.Context, req protocols.HttpRequest, baseURL, basePath string, data map[string]map[string]string) (string, error) {

	for mainKey, subKeys := range data {
		// 构建完整的请求 URL: 处理的URL + 静态路径 + JSON主键
		var requestURL string
		// 避免重复的/
		if !strings.HasPrefix(mainKey, "/") {
			requestURL = fmt.Sprintf("%s/%s/%s", baseURL, basePath, mainKey)
		} else {
			requestURL = fmt.Sprintf("%s/%s%s", baseURL, basePath, mainKey)
		}

		// 下载文件并计算md5值
		md5Value, err := d.DownloadAndHash(ctx, req, requestURL)
		if err != nil {
			// 继续尝试下一个主键
			continue
		}

		// 遍历子健的键值对 匹配计算出的 MD5 值
		for subKey, expectedMD5 := range subKeys {
			if md5Value == expectedMD5 {
				return subKey, nil // 找到第一个匹配就返回
			}
		}
	}
	return "", fmt.Errorf("未在型号版本文件中找到匹配的版本/型号")
}

// 处理常规文件和 zip 文件，并计算 MD5 值
func (d *FortiGateDetector) DownloadAndHash(ctx context.Context, req protocols.HttpRequest, fileURL string) (string, error) {
	// 发起请求
	req.URL = fileURL
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Err != nil {
		return "", resp.Err
	}
	hash := md5.New()
	// 直接写入字节切片到哈希对象
	if _, err = hash.Write(resp.Body); err != nil {
		return "", err
	}
	calculatedMD5 := hex.EncodeToString(hash.Sum(nil))

	return calculatedMD5, nil

	//// 检查是否为zip文件
	//if strings.HasSuffix(strings.ToLower(fileURL), ".zip") {
	//	// 通过 bytes.Reader 和 zip.NewReader 在内存中解压
	//	zipReader, err := zip.NewReader(bytes.NewReader(resp.Body), int64(len(resp.Body)))
	//	if err != nil {
	//		return "", fmt.Errorf("创建 zip 读取器失败: %s", err)
	//	}
	//
	//	// 查找 pkginfo.json
	//	pkginfoMD5 := ""
	//	// 遍历zip中所有文件
	//	for _, file := range zipReader.File {
	//		if strings.EqualFold(file.Name, "pkginfo.json") { // 不区分大小写匹配文件名
	//			// 在 zip 中找到 pkginfo.json，正在计算其 MD5
	//			rc, err := file.Open()
	//			if err != nil {
	//				return "", fmt.Errorf("打开 zip 中的 pkginfo.json 失败: %s", err)
	//			}
	//			defer rc.Close()
	//
	//			hash := md5.New()
	//			if _, err := io.Copy(hash, rc); err != nil {
	//				return "", fmt.Errorf("计算 pkginfo.json 的 MD5 失败: %s", err)
	//			}
	//			pkginfoMD5 = hex.EncodeToString(hash.Sum(nil))
	//			return pkginfoMD5, nil
	//		}
	//	}
	//	return pkginfoMD5, nil
	//} else {
	//	// 非zip文件 常规计算
	//	hash := md5.New()
	//	// 直接写入字节切片到哈希对象
	//	if _, err := hash.Write(resp.Body); err != nil {
	//		return "", err
	//	}
	//	calculatedMD5 := hex.EncodeToString(hash.Sum(nil))
	//
	//	return calculatedMD5, nil
	//}
}

func (d *FortiGateDetector) MatchSpecificPaths(ctx context.Context, req protocols.HttpRequest, baseURL, basePath string) (string, error) {
	// 特殊路径
	specificPaths := []string{
		"api/v2/static/fweb_build.json",
		"ng/vpn/map/map_app/index.html",
		"ng/vpn/map/pkginfo.json",
		"ng/vpn/map/map_app.zip",
	}

	// 循环访问特殊路径
	for _, path := range specificPaths {
		requestURL := fmt.Sprintf("%s/%s/%s", baseURL, basePath, path)

		content, err := d.DownloadFileContent(ctx, req, requestURL)
		if err != nil {
			// 继续尝试下一个特定路径，不返回错误
			continue
		}

		if path == "api/v2/static/fweb_build.json" {
			var data struct {
				CONFIG struct {
					Model    string `json:"CONFIG_MODEL"`        // 型号
					Major    int    `json:"CONFIG_MAJOR_NUM"`    // 主版本号
					Minor    int    `json:"CONFIG_MINOR_NUM"`    // 次版本号
					Patch    int    `json:"CONFIG_PATCH_NUM"`    // 补丁版本
					BuildNum int    `json:"CONFIG_BUILD_NUMBER"` // 构建编号
				} `json:"CONFIG"`
			}
			// 解析JSON
			err = json.Unmarshal([]byte(content), &data)
			if err == nil {
				versionString := fmt.Sprintf("%d.%d.%d",
					data.CONFIG.Major,
					data.CONFIG.Minor,
					data.CONFIG.Patch,
				)

				return versionString, nil // 示例:7.2.8
			}

		} else if path == "ng/vpn/map/map_app/index.html" {
			var versionRegex = regexp.MustCompile(`(?i)([A-Za-z0-9]+)_([A-Za-z0-9]+)_vpn_map_(\d+\.\d+\.\d+)`) // 忽略大小写
			matches := versionRegex.FindStringSubmatch(content)
			if len(matches) >= 4 {
				//fmt.Printf("完整匹配: %s\n", matches[0])      // ABC_100X_vpn_map_7.2.8
				//fmt.Printf("分组1 (前缀1): %s\n", matches[1]) // ABC
				//fmt.Printf("分组2 (前缀2): %s\n", matches[2]) // 100X
				//fmt.Printf("分组3 (版本号): %s\n", matches[3]) // 7.2.8
				//versionString := fmt.Sprintf("%s %s", matches[2], matches[3])
				versionString := fmt.Sprintf("%s", matches[3])
				return versionString, nil // 示例:7.2.8
			}

		} else {
			//示例：{"platform":"FGT60F","ver":7,"build":1639,"branchpt":1639,"mr":2,"ver_s":"FGT60F v7.2.8 build1639(Branchpt:1639) 240313 (GA)","chksum":"185809022271531764d032b6ca8516b2ea98eed8975cc6df0ba1c7d832e89286"}
			// 尝试从文件内容中匹配版本格式
			//var versionRegex = regexp.MustCompile(`(?i)([A-Z0-9]{2,})[\s_]*?(v\d+\.\d+\.\d+)`) // 忽略大小写
			var versionRegex = regexp.MustCompile(`(?i)([A-Z0-9]{2,})[\s_]*?v(\d+\.\d+\.\d+)`)
			matches := versionRegex.FindStringSubmatch(content)
			if len(matches) > 2 { // 确保匹配到至少两个捕获组 (型号和版本)
				//versionString := fmt.Sprintf("%s %s", matches[1], matches[2])
				versionString := fmt.Sprintf("%s", matches[2])
				return versionString, nil // 示例:7.2.8
			}

		}
	}

	return "", fmt.Errorf("未在特定路径中找到版本信息")
}

// 下载并获取文件内容
func (d *FortiGateDetector) DownloadFileContent(ctx context.Context, req protocols.HttpRequest, fileURL string) (string, error) {
	// 发起请求
	req.URL = fileURL
	resp, err := d.httpClient.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Err != nil {
		return "", resp.Err
	}

	// 检查是否为zip文件
	if strings.HasSuffix(strings.ToLower(fileURL), ".zip") {
		// 通过 bytes.Reader 和 zip.NewReader 在内存中解压
		zipReader, err := zip.NewReader(bytes.NewReader(resp.Body), int64(len(resp.Body)))
		if err != nil {
			return "", fmt.Errorf("创建 zip 读取器失败: %s", err)
		}

		// 遍历zip中所有文件
		for _, file := range zipReader.File {
			if strings.EqualFold(file.Name, "pkginfo.json") { // 不区分大小写匹配文件名
				// 在 zip 中找到 pkginfo.json，并返回其内容
				rc, err := file.Open()
				if err != nil {
					return "", fmt.Errorf("打开 zip 中的 pkginfo.json 失败: %s", err)
				}
				defer rc.Close()

				// 读取文件内容
				content, err := io.ReadAll(rc)
				if err != nil {
					return "", fmt.Errorf("读取 pkginfo.json 内容失败: %s", err)
				}

				return string(content), nil
			}
		}
		return "", nil
	}
	// 其他文件正常返回
	return string(resp.Body), nil
}

// 3、使用版本文件进行匹配 优先返回唯一匹配 否则去重返回所有结果
func (d *FortiGateDetector) MatchUniqueVersion(ctx context.Context, req protocols.HttpRequest, baseURL, basePath string, data map[string]map[string]string) (string, error) {
	// 用于收集所有匹配到的版本，以便在没有唯一匹配时返回去重后的列表
	allMatchedVersions := make(map[string]bool)

	for mainKey, subKeys := range data {
		// 构建完整的请求 URL: 处理的URL + 静态路径 + JSON主键
		var requestURL string
		if !strings.HasPrefix(mainKey, "/") {
			requestURL = fmt.Sprintf("%s/%s/%s", baseURL, basePath, mainKey)
		} else {
			requestURL = fmt.Sprintf("%s/%s%s", baseURL, basePath, mainKey)
		}

		// 下载文件并计算md5值
		md5Value, err := d.DownloadAndHash(ctx, req, requestURL)
		if err != nil {
			// 继续尝试下一个主键
			continue
		}

		// 收集当前主键的所有匹配项
		currentFileMatches := []string{}
		for subKey, expectedMD5 := range subKeys {
			if md5Value == expectedMD5 {
				currentFileMatches = append(currentFileMatches, subKey)
				allMatchedVersions[subKey] = true // 记录所有匹配到的版本
			}
		}

		// 如果当前文件有且仅有一个匹配，则立即返回
		if len(currentFileMatches) == 1 {
			// ver.json 成功找到唯一匹配
			return currentFileMatches[0], nil
		}
	}

	// 如果所有主键都遍历完，但没有找到唯一的匹配结果
	if len(allMatchedVersions) > 0 {
		var uniqueResults []string
		for ver := range allMatchedVersions {
			uniqueResults = append(uniqueResults, ver)
		}
		// 按字母顺序排序，以便输出稳定
		sort.Strings(uniqueResults)
		return strings.Join(uniqueResults, ", "), nil
	}

	return "", fmt.Errorf("未在库中找到任何匹配的版本信息")
}

// formatVersion 将不同格式的版本号统一转换为 x.y.z 格式
func (d *FortiGateDetector) formatVersion(raw string) string {
	// 处理类似 "200E_7_2_8" 或 "40F_7_2_8" 的格式
	parts := strings.Split(raw, "_")
	if len(parts) > 1 {
		// 取最后三个部分作为版本号
		if len(parts) >= 4 {
			parts = parts[len(parts)-3:]
		}
		return strings.Join(parts, ".")
	}

	// 处理类似 "7_2_8" 的格式
	if strings.Contains(raw, "_") {
		return strings.ReplaceAll(raw, "_", ".")
	}

	// 已经是 "7.2.8" 格式或其他格式，直接返回
	return raw
}
