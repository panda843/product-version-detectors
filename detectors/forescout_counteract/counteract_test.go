package forescout_counteract

import (
	"context"
	"fmt"
	"github.com/panda843/product-version-detectors/protocols"
	"testing"
)

func TestNewCiscoASADetector(t *testing.T) {
	httpClient := protocols.NewDefaultHTTPClient()
	tcpClient := protocols.NewDefaultTCPClient()
	udpClient := protocols.NewDefaultUDPClient()
	detector := NewCounteractDetector(httpClient, tcpClient, udpClient)
	if detector == nil {
		t.Errorf("NewCounteractDetector() returned nil")
	}
	v, e := detector.Detect(context.Background(), "ASA_configuration_utility", "f5", "https://172.16.21.190")
	if e != nil {
		panic(e)
	}
	fmt.Println("NewCounteractDetector detector:", v)
}
