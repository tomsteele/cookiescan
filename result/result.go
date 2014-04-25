package cookiescan

type Result struct {
	Host  string `json:"host"`
	Ports Ports  `json:"ports"`
}

type Port struct {
	Port       int      `json:"port"`
	Service    string   `json:"service"`
	State      string   `json:"state"`
	Confidence int      `json:"confidence"`
	Reason     []string `json:"reason"`
}

type Ports []Port

func (p Ports) Len() int           { return len(p) }
func (p Ports) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p Ports) Less(i, j int) bool { return p[i].Port < p[j].Port }
