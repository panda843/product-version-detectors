package cisco_secure_email_and_web_manager_firmware

import (
	"context"
	"fmt"
	"testing"

	"github.com/panda843/product-version-detectors/protocols"
)

func TestNewCiscoEsaDetector(t *testing.T) {
	httpClient := protocols.NewDefaultHTTPClient()
	tcpClient := protocols.NewDefaultTCPClient()
	udpClient := protocols.NewDefaultUDPClient()
	detector := NewCiscoSmaZeusDetector(httpClient, tcpClient, udpClient)
	if detector == nil {
		t.Errorf("NewCiscoSmaZeusDetector() returned nil")
	}
	v, e := detector.Detect(context.Background(), "secure_email_and_web_manager_firmware", "cisco", "https://103.110.83.23")
	if e != nil {
		panic(e)
	}
	fmt.Println("NewCiscoSmaZeusDetector detector:", v)
}
