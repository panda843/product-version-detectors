package paloalto_panos

import (
	"context"
	"fmt"
	"github.com/panda843/product-version-detectors/detectors"
	"github.com/panda843/product-version-detectors/protocols"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PanOSDetector 是版本检测器
type PanOSDetector struct {
	httpClient protocols.HTTPClient
	versionMap *VersionMap
}

// VersionMap 结构体用于存储日期和版本的映射关系
type VersionMap struct {
	versions map[string][]string
}

// 定义静态资源路径数组
var staticResources = []string{
	"/login/images/favicon.ico",
	"/js/Pan.js",
	"/global-protect/portal/images/bg.png",
	"/global-protect/portal/css/login.css",
	"/global-protect/portal/images/favicon.ico",
}

// NewPanOSDetector 创建一个新的版本检测器
func NewPanOSDetector(httpClient protocols.HTTPClient, _ protocols.TCPClient, _ protocols.UDPClient) detectors.Detector {
	return &PanOSDetector{
		httpClient: httpClient,
		versionMap: &VersionMap{versions: predefinedVersions()},
	}
}

// Detect 检测版本
func (d *PanOSDetector) Detect(ctx context.Context, cnProduct, vendor, target string) (string, error) {
	// 如果用户输入的目标没有指定协议，默认加上 https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 获取 ETag 值
	etagValues, err := d.fetchETags(ctx, target)
	if err != nil {
		return "", err
	}

	// 从 ETag 值中提取日期
	dates, err := extractDates(etagValues)
	if err != nil {
		return "", err
	}

	// 计算版本百分比
	percentages := d.versionMap.CalculatePercentage(dates)
	if len(percentages) == 0 {
		return "", fmt.Errorf("no versions matched the detected dates")
	}

	// 返回百分比最高的版本
	version := getMostProbableVersion(percentages)
	if strings.Contains(version, "-") {
		version = getMainVersion(version)
	}

	return version, nil
}

// 提取主要版本号
func getMainVersion(versionDesc string) string {
	// 按连字符分割字符串
	parts := strings.SplitN(versionDesc, "-", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return versionDesc // 如果无法分割，返回原字符串
}

// 提取ETag中的日期
func extractDates(etags []string) ([]string, error) {
	var dates []string
	for _, etag := range etags {
		cleanedEtag := strings.Trim(etag, "\"")
		extractedPart := extractTimestampPart(cleanedEtag)

		timestamp, err := strconv.ParseUint(extractedPart, 16, 64)
		if err != nil {
			continue // 忽略解析失败的ETag
		}

		date := time.Unix(int64(timestamp), 0).Format("2006-01-02")
		dates = append(dates, date)
	}

	if len(dates) == 0 {
		return nil, fmt.Errorf("no valid dates extracted from ETags")
	}
	return dates, nil
}

// 提取ETag中的时间戳部分
func extractTimestampPart(etag string) string {
	if strings.Contains(etag, "-") {
		return etag[:8]
	}
	return etag[len(etag)-8:]
}

// fetchETags 遍历所有预定义的静态资源，尝试获取它们的ETag值
// 对每个资源会依次尝试HTTPS和HTTP协议，获取到的有效ETag会被收集
// 返回值：成功获取的ETag切片，若所有请求失败则返回错误
func (d *PanOSDetector) fetchETags(ctx context.Context, baseURL string) ([]string, error) {
	var etagValues []string

	// 遍历预定义的静态资源列表，尝试获取每个资源的ETag
	for _, resource := range staticResources {
		// 对单个资源尝试获取ETag，自动处理协议切换
		etag, err := d.fetchResourceETag(ctx, baseURL, resource)
		if err == nil && etag != "" {
			etagValues = append(etagValues, etag)
		}
	}

	// 检查是否获取到任何有效ETag
	if len(etagValues) == 0 {
		return nil, fmt.Errorf("failed to retrieve any ETags from target")
	}
	return etagValues, nil
}

// 获取单个资源的ETag
func (d *PanOSDetector) fetchResourceETag(ctx context.Context, baseURL, resourcePath string) (string, error) {
	for _, scheme := range []string{"https://", "http://"} {
		// 尝试多种协议（HTTPS优先，失败则尝试HTTP）
		fullURL := replaceScheme(baseURL, scheme) + resourcePath

		// 发送HTTP请求获取资源
		resp, err := d.httpClient.Do(ctx, protocols.HttpRequest{
			Method:          "GET",
			URL:             fullURL,
			Timeout:         10 * time.Second,
			FollowRedirects: true,
			MaxRedirects:    3,
			MaxRetries:      2,
			RetryDelay:      1 * time.Second,
		})

		if err == nil {
			return resp.Headers.Get("ETag"), nil
		}
	}

	// 所有协议尝试均失败
	return "", fmt.Errorf("failed to fetch resource: %s", resourcePath)
}

// 替换URL协议
func replaceScheme(url, scheme string) string {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return scheme + url[strings.Index(url, "//")+2:]
	}
	return scheme + url
}

// GetVersions 根据日期列表获取对应的版本列表
// 返回一个字符串指针切片，每个元素对应输入日期的版本信息：
// - 若日期存在映射，返回拼接后的版本字符串指针（如 "6.0.0, 6.0.1"）
// - 若日期不存在映射，返回 nil
func (vm *VersionMap) GetVersions(dates []string) []*string {
	var result []*string // 存储结果的指针切片

	// 遍历输入的日期列表
	for _, date := range dates {
		// 检查日期是否存在于映射表中
		if versions, ok := vm.versions[date]; ok {
			// 存在：将版本列表拼接为字符串（如 "6.0.0, 6.0.1"）
			versionStr := strings.Join(versions, ", ")
			// 将字符串地址添加到结果切片（避免循环变量复用问题）
			result = append(result, &versionStr)
		} else {
			// 不存在：添加 nil 表示无对应版本
			result = append(result, nil)
		}
	}

	return result
}

// CalculatePercentage 根据日期列表计算每个版本的百分比
// 返回一个映射表，键为版本号，值为该版本在所有日期中出现的百分比
func (vm *VersionMap) CalculatePercentage(dates []string) map[string]float64 {
	versionCount := make(map[string]int) // 统计每个版本的出现次数
	totalCount := 0                      // 总版本计数（可能大于日期数，因一个日期可能对应多个版本）

	// 遍历输入的日期列表
	for _, date := range dates {
		// 检查日期是否存在于映射表中
		if versions, ok := vm.versions[date]; ok {
			// 存在：遍历该日期对应的所有版本
			for _, version := range versions {
				// 对应版本计数+1
				versionCount[version]++
				// 总计数+1
				totalCount++
			}
		}
	}

	// 计算每个版本的百分比
	percentages := make(map[string]float64)
	for version, count := range versionCount {
		// 百分比 = (版本计数 / 总计数) * 100
		percentages[version] = float64(count) / float64(totalCount) * 100
	}

	return percentages
}

// 获取概率最高的版本
// 输入参数：percentages - 版本号到出现概率的映射表（如：map["6.0.0": 80, "6.0.1": 20]）
// 返回值：  概率最高的版本号，若输入为空则返回空字符串
func getMostProbableVersion(percentages map[string]float64) string {
	// 处理空输入场景
	if len(percentages) == 0 {
		return ""
	}

	// 定义版本数据结构体，用于存储版本号和对应概率
	type versionData struct {
		version    string  // 软件版本号（如 "6.0.0"）
		percentage float64 // 该版本在所有检测结果中的出现概率（单位：%）
	}

	// 转换映射表为结构体切片，便于排序处理
	var versions []versionData
	for version, percentage := range percentages {
		versions = append(versions, versionData{version, percentage})
	}

	// 自定义排序规则：
	// 1. 首先按概率降序排列（概率高的版本排在前面）
	// 2. 当概率相同时，按版本号升序排列（如 "6.0.0" < "6.0.1"）
	sort.Slice(versions, func(i, j int) bool {
		if versions[i].percentage != versions[j].percentage {
			return versions[i].percentage > versions[j].percentage
		}
		return versions[i].version < versions[j].version
	})

	// 返回排序后的第一个元素（概率最高的版本）
	return versions[0].version
}

// 获取预定义的版本映射
func predefinedVersions() map[string][]string {
	return map[string][]string{
		"2013-12-23": {"6.0.0"},
		"2014-02-26": {"6.0.1"},
		"2014-04-18": {"6.0.2"},
		"2014-05-29": {"6.0.3"},
		"2014-07-30": {"6.0.4"},
		"2014-09-04": {"6.0.5"},
		"2014-10-07": {"6.0.5-h3", "6.0.6"},
		"2014-11-18": {"6.0.7"},
		"2015-01-13": {"6.0.8"},
		"2015-02-27": {"6.0.9"},
		"2015-04-22": {"6.0.10", "6.1.4"},
		"2015-08-12": {"6.0.11"},
		"2015-11-19": {"6.0.12"},
		"2016-02-13": {"6.0.13"},
		"2016-06-28": {"6.0.14"},
		"2016-10-05": {"6.0.15", "6.1.15"},
		"2014-10-17": {"6.1.0"},
		"2014-11-13": {"6.1.1"},
		"2015-01-23": {"6.1.2"},
		"2015-03-10": {"6.1.3"},
		"2015-06-17": {"6.1.5"},
		"2015-07-23": {"6.1.6"},
		"2015-09-10": {"6.1.7"},
		"2015-11-04": {"6.1.8"},
		"2016-01-08": {"6.1.9"},
		"2016-02-12": {"6.1.10"},
		"2016-04-02": {"6.1.11"},
		"2016-05-21": {"6.1.12"},
		"2016-07-15": {"6.1.13"},
		"2016-08-10": {"6.1.14"},
		"2017-01-10": {"6.1.16"},
		"2017-04-14": {"6.1.17"},
		"2017-07-14": {"6.1.18"},
		"2017-11-05": {"6.1.19"},
		"2018-02-13": {"6.1.20"},
		"2018-05-25": {"6.1.21"},
		"2018-10-15": {"6.1.22"},
		"2015-07-03": {"7.0.1"},
		"2015-08-21": {"7.0.2"},
		"2015-10-08": {"7.0.3"},
		"2015-12-12": {"7.0.4"},
		"2016-01-30": {"7.0.5"},
		"2016-02-17": {"7.0.5-h2"},
		"2016-03-12": {"7.0.6"},
		"2016-04-19": {"7.0.7"},
		"2016-06-11": {"7.0.8"},
		"2016-07-27": {"7.0.9"},
		"2016-08-29": {"7.0.10"},
		"2016-10-20": {"7.0.11"},
		"2016-12-06": {"7.0.12"},
		"2016-12-29": {"7.0.13"},
		"2017-02-08": {"7.0.14"},
		"2017-04-12": {"7.0.15"},
		"2017-05-30": {"7.0.16"},
		"2017-07-10": {"7.0.17"},
		"2017-08-16": {"7.0.18"},
		"2017-11-10": {"7.0.19"},
		"2016-03-16": {"7.1.0"},
		"2016-04-06": {"7.1.1"},
		"2016-05-03": {"7.1.2"},
		"2016-06-21": {"7.1.3"},
		"2016-08-02": {"7.1.4"},
		"2016-08-12": {"7.1.4-h2"},
		"2016-09-24": {"7.1.5"},
		"2016-11-09": {"7.1.6"},
		"2016-12-17": {"7.1.7"},
		"2017-02-14": {"7.1.8"},
		"2017-03-27": {"7.1.9"},
		"2017-06-16": {"7.1.9-h4"},
		"2017-05-05": {"7.1.10"},
		"2017-06-29": {"7.1.11"},
		"2017-08-18": {"7.1.12"},
		"2017-09-28": {"7.1.13"},
		"2017-11-13": {"7.1.14"},
		"2018-01-05": {"7.1.15"},
		"2018-02-20": {"7.1.16"},
		"2018-04-11": {"7.1.17"},
		"2018-06-06": {"7.1.18", "8.1.2"},
		"2018-07-16": {"7.1.19"},
		"2018-09-07": {"7.1.20"},
		"2018-10-31": {"7.1.21"},
		"2018-12-17": {"7.1.22"},
		"2019-03-09": {"7.1.23"},
		"2019-06-14": {"7.1.24"},
		"2019-08-15": {"7.1.24-h1", "8.1.9-h4", "8.0.19-h1"},
		"2019-08-30": {"7.1.25"},
		"2020-04-21": {"7.1.26"},
		"2017-01-25": {"8.0.0"},
		"2017-03-09": {"8.0.1"},
		"2017-04-25": {"8.0.2"},
		"2017-06-08": {"8.0.3"},
		"2017-06-22": {"8.0.3-h4"},
		"2017-07-21": {"8.0.4"},
		"2017-09-10": {"8.0.5"},
		"2017-11-04": {"8.0.6"},
		"2017-11-16": {"8.0.6-h3"},
		"2017-12-24": {"8.0.7"},
		"2018-01-31": {"8.0.8"},
		"2018-03-23": {"8.0.9"},
		"2018-05-04": {"8.0.10"},
		"2018-06-29": {"8.0.11-h1"},
		"2018-08-04": {"8.0.12"},
		"2018-09-18": {"8.0.13"},
		"2018-11-17": {"8.0.14"},
		"2018-12-08": {"8.0.15"},
		"2019-02-12": {"8.0.16"},
		"2019-03-22": {"8.0.17"},
		"2019-05-13": {"8.0.18"},
		"2019-06-20": {"8.0.19"},
		"2019-10-18": {"8.0.20"},
		"2018-03-01": {"8.1.0"},
		"2018-04-23": {"8.1.1"},
		"2018-08-08": {"8.1.3"},
		"2018-10-05": {"8.1.4"},
		"2018-11-21": {"8.1.5"},
		"2019-01-17": {"8.1.6"},
		"2019-01-23": {"8.1.6-h2"},
		"2019-03-13": {"8.1.7"},
		"2019-04-30": {"8.1.8"},
		"2019-06-17": {"8.1.8-h5"},
		"2019-07-03": {"8.1.9"},
		"2019-08-21": {"8.1.10"},
		"2019-10-12": {"8.1.11"},
		"2019-12-10": {"8.1.12"},
		"2020-01-25": {"8.1.13"},
		"2020-04-01": {"8.1.14"},
		"2020-04-18": {"8.1.14-h2"},
		"2020-06-13": {"8.1.15"},
		"2020-06-23": {"8.1.15-h3"},
		"2020-08-12": {"8.1.16"},
		"2020-09-23": {"8.1.17"},
		"2020-11-17": {"8.1.18"},
		"2019-01-29": {"9.0.0"},
		"2019-03-26": {"9.0.1"},
		"2019-05-07": {"9.0.2"},
		"2019-06-21": {"9.0.2-h4"},
		"2019-07-10": {"9.0.3"},
		"2019-07-18": {"9.0.3-h2"},
		"2019-08-14": {"9.0.3-h3"},
		"2019-09-10": {"9.0.4"},
		"2019-11-07": {"9.0.5"},
		"2020-01-24": {"9.0.6", "9.1.1"},
		"2020-03-13": {"9.0.7"},
		"2020-04-07": {"9.0.8"},
		"2020-06-20": {"9.0.9", "9.1.3"},
		"2020-08-20": {"9.0.10"},
		"2020-10-07": {"9.0.11"},
		"2020-11-24": {"9.0.12"},
		"2019-12-11": {"9.1.0"},
		"2019-12-21": {"9.1.0-h3"},
		"2020-03-30": {"9.1.2"},
		"2020-04-09": {"9.1.2-h1"},
		"2020-06-26": {"9.1.3-h1"},
		"2020-07-27": {"9.1.4"},
		"2020-09-16": {"9.1.5"},
		"2020-10-23": {"9.1.6"},
		"2020-12-15": {"9.1.7"},
		"2021-02-05": {"9.1.8"},
		"2020-07-16": {"10.0.0"},
		"2020-08-28": {"10.0.1"},
		"2020-10-27": {"10.0.2"},
		"2020-12-07": {"10.0.3"},
		"2022-09-06": {"10.1.7"},
		"2022-02-26": {"10.2.0"},
		"2024-04-18": {"10.2.0-h3", "10.2.1-h2", "10.2.2-h5", "10.2.3-h13", "10.2.4-h16", "11.0.0-h3", "11.0.1-h4"},
		"2022-04-13": {"10.2.1"},
		"2022-06-02": {"10.2.2"},
		"2022-08-08": {"10.2.2-h2"},
		"2022-09-27": {"10.2.3"},
		"2022-12-09": {"10.2.3-h2"},
		"2023-02-08": {"10.2.3-h4"},
		"2023-11-03": {"10.2.3-h9", "11.0.0-h1"},
		"2023-12-19": {"10.2.3-h11", "10.2.3-h12"},
		"2023-03-26": {"10.2.4", "11.0.1"},
		"2023-05-12": {"10.2.4-h2"},
		"2023-06-29": {"10.2.4-h3"},
		"2023-07-25": {"10.2.4-h4"},
		"2023-08-15": {"10.2.5"},
		"2024-04-16": {"10.2.5-h6", "10.2.6-h3", "11.0.2-h4", "11.0.3-h10", "11.1.0-h3", "11.1.1-h1"},
		"2023-09-20": {"10.2.6"},
		"2024-01-03": {"10.2.6-h1"},
		"2023-11-02": {"10.2.7"},
		"2023-12-16": {"10.2.7-h3"},
		"2024-02-28": {"10.2.7-h6"},
		"2024-04-15": {"10.2.7-h8", "10.2.8-h3"},
		"2024-02-08": {"10.2.8"},
		"2024-03-30": {"10.2.9"},
		"2024-04-14": {"10.2.9-h1", "11.0.4-h1", "11.1.2-h3"},
		"2022-11-17": {"11.0.0"},
		"2023-06-23": {"11.0.2"},
		"2023-10-26": {"11.0.3"},
		"2024-01-13": {"11.0.3-h3"},
		"2024-02-20": {"11.0.3-h5", "11.0.3-h5"},
		"2024-04-07": {"11.0.4"},
		"2024-04-17": {"11.0.4-h2"},
		"2023-10-31": {"11.1.0"},
		"2023-12-22": {"11.1.0-h2", "11.1.1"},
		"2024-02-23": {"11.1.2"},
		"2024-03-09": {"11.1.2-h1"},
		"2024-06-22": {"10.2.10"},
	}
}
