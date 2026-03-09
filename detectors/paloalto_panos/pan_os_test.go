package paloalto_panos

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
	detector := NewPanOSDetector(httpClient, tcpClient, udpClient)
	if detector == nil {
		t.Errorf("NewPanOSDetector() returned nil")
	}
	v, e := detector.Detect(context.Background(), "pan-os", "paloaltonetworks", "https://58.33.189.91:4443")
	if e != nil {
		panic(e)
	}
	fmt.Println("NewPanOSDetector detector:", v)
}
