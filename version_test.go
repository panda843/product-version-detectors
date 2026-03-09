package version

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/panda843/product-version-detectors/protocols"
)

func TestNew(t *testing.T) {
	version, err := New().Check(context.Background(), "openssh", "OpenSsh", "openssh", "172.16.21.209:22")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ssh version:", version)
	//fmt.Println("===================================================")
	//nginxVersion, _ := New().Check(context.Background(), "nginx", "Nginx", "f5", "http://172.16.21.209")
	//fmt.Println("nginx version:", nginxVersion)
}

type CustomHTTPClient struct {
	client *http.Client
}

func NewCustomHTTPClient() protocols.HTTPClient {
	return &CustomHTTPClient{client: &http.Client{Timeout: 10 * time.Second}}
}

// Do 执行HTTP请求
func (c *CustomHTTPClient) Do(ctx context.Context, req protocols.HttpRequest) (*protocols.Response, error) {
	return nil, fmt.Errorf("custom http client error")
}
