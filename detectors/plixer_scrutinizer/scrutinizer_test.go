package plixer_scrutinizer

import (
	"context"
	"fmt"
	"github.com/panda843/product-version-detectors/protocols"
	"testing"
)

func TestNewPlixerScrutinizerDetector(t *testing.T) {
	httpClient := protocols.NewDefaultHTTPClient()
	tcpClient := protocols.NewDefaultTCPClient()
	udpClient := protocols.NewDefaultUDPClient()
	detector := NewPlixerScrutinizerDetector(httpClient, tcpClient, udpClient)
	if detector == nil {
		t.Errorf("NewPlixerScrutinizerDetector() returned nil")
	}
	v, e := detector.Detect(context.Background(), "scrutinizer", "plixer", "https://185.19.97.67")
	if e != nil {
		panic(e)
	}
	fmt.Println("scrutinizer detector:", v)
}
