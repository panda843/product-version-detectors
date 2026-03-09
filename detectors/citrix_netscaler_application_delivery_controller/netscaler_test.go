package citrix_netscaler_application_delivery_controller

import (
	"context"
	"fmt"
	"github.com/panda843/product-version-detectors/protocols"
	"testing"
)

func TestNewCiscoEsaDetector(t *testing.T) {
	httpClient := protocols.NewDefaultHTTPClient()
	tcpClient := protocols.NewDefaultTCPClient()
	udpClient := protocols.NewDefaultUDPClient()
	detector := NewCitrixNetScalerDetector(httpClient, tcpClient, udpClient)
	if detector == nil {
		t.Errorf("NewCiscoISEDetector() returned nil")
	}
	v, e := detector.Detect(context.Background(), "big-ip_configuration_utility", "f5", "http://13.94.225.233")
	if e != nil {
		panic(e)
	}
	fmt.Println("NewCiscoISEDetector detector:", v)
}
