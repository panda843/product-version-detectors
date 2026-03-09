package mapping

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed resources/*.json
var fs embed.FS

// LoadEmbeddedJSONData 从嵌入的文件系统加载JSON数据
func LoadEmbeddedJSONData(filePath string) (map[string]map[string]string, error) {
	data, err := fs.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取嵌入文件失败: %w", err)
	}

	var result map[string]map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("解析JSON失败: %w", err)
	}
	return result, nil
}
