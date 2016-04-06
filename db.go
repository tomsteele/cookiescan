package cookiescan

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"text/tabwriter"
)

type Services []Service

func (s Services) Len() int           { return len(s) }
func (s Services) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s Services) Less(i, j int) bool { return s[i].Port < s[j].Port }

type Service struct {
	Port       int      `json:"port"`
	Service    string   `json:"service"`
	State      string   `json:"state"`
	Confidence int      `json:"confidence"`
	Reason     []string `json:"reason"`
}

type Store struct {
	Hosts map[string][]Service
}

type Result struct {
	Host     string   `json:"host"`
	Services Services `json:"services"`
}

func (s *Store) Add(ip string, port int, flags string) {
	services := s.Hosts[ip]
	if services == nil {
		return
	}
	var found bool
	for i, service := range services {
		if service.Port == port {
			services[i].Reason = append(services[i].Reason, flags)
			services[i].Confidence = len(services[i].Reason)
			found = true
		}
	}
	if !found {
		services = append(services, Service{
			Port:       port,
			Confidence: 1,
			State:      "open",
			Service:    "unknown",
			Reason:     []string{flags},
		})
	}
	s.Hosts[ip] = services
}

func (s *Store) build(confidence int) []Result {
	sMap, _ := buildServices()
	results := []Result{}
	for host, services := range s.Hosts {
		result := Result{Host: host}
		for i := range services {
			if def, ok := sMap[int(services[i].Port)]; ok {
				services[i].Service = def
			}
			if services[i].Confidence >= confidence {
				result.Services = append(result.Services, services[i])
			}
		}
		if len(result.Services) > 0 {
			sort.Sort(result.Services)
			results = append(results, result)
		}
	}
	return results
}

func (s *Store) JSON(confidence int, fname string) {
	results := s.build(confidence)
	j, _ := json.MarshalIndent(results, "", "    ")
	ioutil.WriteFile(fname, j, 0664)
}

func (s *Store) Tabbed(confidence int) {
	results := s.build(confidence)
	w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
	for _, r := range results {
		fmt.Fprintf(w, "\nHost: %s\n", r.Host)
		fmt.Fprintln(w, "Port\tState\tService\tConfidence\tReason")
		for _, p := range r.Services {
			fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\n", p.Port, p.State, p.Service, p.Confidence, p.Reason)
		}
		w.Flush()
	}
}

func NewStore(ips []string) *Store {
	db := &Store{
		Hosts: make(map[string][]Service),
	}
	for _, ip := range ips {
		db.Hosts[ip] = []Service{}
	}
	return db
}
