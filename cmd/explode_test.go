package main

import "testing"

const (
	dashRange    = "1-20"
	singlePort   = "4444"
	dashAndComma = "1,2,3,4,5-10"
)

func TestDashSplit(t *testing.T) {
	ports := []int{}
	err := dashSplit(dashRange, &ports)
	if err != nil {
		t.Error(err)
	}
	expected := 20
	if len(ports) != expected {
		t.Errorf("Expected length of %d and got %d\n", expected, len(ports))
	}
}

func TestConvertAndAddPort(t *testing.T) {
	ports := []int{}
	err := convertAndAddPort(singlePort, &ports)
	if err != nil {
		t.Error(err)
	}
	if ports[0] != 4444 {
		t.Error("Expected 4444 and got", ports[0])
	}
}

func TestExplode(t *testing.T) {
	ports, err := explode(dashAndComma)
	if err != nil {
		t.Error(err)
	}
	expected := 10
	if len(ports) != expected {
		t.Errorf("Expexted length of %d and got %d\n", expected, len(ports))
	}
}
