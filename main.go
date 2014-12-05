package main

import (
	"encoding/json"
	"fmt"
	"github.com/docopt/docopt-go"
	"github.com/miekg/pcap"
	"github.com/tomsteele/cookiescan/result"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"text/tabwriter"
	"time"
)

type empty struct{}

func main() {
	args, err := docopt.Parse(usage, nil, true, "cookiescan 0.1", false)
	if err != nil {
		log.Fatal("Error parsing usage. Error: ", err.Error())
	}
	host := args["<target>"].(string)
	ports, err := explode(args["-p"].(string))
	if err != nil {
		log.Fatal(err.Error())
	}

	var ip string
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil {
			log.Fatal("Could not resolve hostname. Error: ", err.Error())
		}
		ip = ips[0].String()
	} else {
		ip = host
	}

	minc, err := strconv.Atoi(args["-c"].(string))
	if err != nil {
		log.Fatal("Invalid argument for -c.")
	}
	concurrency, err := strconv.Atoi(args["-g"].(string))
	if err != nil {
		log.Fatal("Invalid argument for -g.")
	}
	ti, err := strconv.Atoi(args["-t"].(string))
	if err != nil {
		log.Fatal("Invalid argument for -t.")
	}
	timeout := time.Duration(ti) * time.Millisecond

	filter := fmt.Sprintf("src %s and ((tcp[13] == 0x11) or (tcp[13] == 0x10) or (tcp[13] == 0x18))", ip)
	var device string
	if args["-i"] != nil {
		device = args["-i"].(string)
	}
	if device == "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal("Error finding interfaces. Error: ", err)
		}
		if len(devs) == 0 {
			log.Fatal("No interfaces found. Are you not running as root?")
		}
		device = devs[0].Name
	}

	h, err := pcap.OpenLive(device, int32(320), true, 500)
	if err != nil {
		log.Fatal(err.Error())
	}
	if err = h.SetFilter(filter); err != nil {
		log.Fatal(err.Error())
	}

	res := make(map[uint16][]string)
	tasks := make(chan int, concurrency)
	track := make(chan empty)

	go func() {
		for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
			select {
			case <-track:
				break
			default:
				if r == 0 {
					continue
				}
				pkt.Decode()
				t := pkt.Headers[1].(*pcap.Tcphdr)
				f := t.FlagsString()
				res[t.SrcPort] = append(res[t.SrcPort], f)
			}
		}
	}()

	for i := 0; i < concurrency; i++ {
		go func() {
			for p := range tasks {
				c, err := net.DialTimeout("tcp", ip+":"+strconv.Itoa(p), timeout)
				if err != nil {
					continue
				}
				c.Close()
			}
		}()
	}

	log.Printf("Staring scan of %s.\n", ip)
	for _, p := range ports {
		tasks <- p
	}
	close(tasks)
	time.Sleep(time.Duration(2 * time.Second))
	track <- empty{}
	close(track)
	h.Close()
	log.Println("Scan complete.")

	services, _ := buildServices()
	results := cookiescan.Result{Host: ip}
	for k, v := range res {
		conf := len(v)
		if conf < minc {
			continue
		}
		service := "unknown"
		if s, ok := services[int(k)]; ok {
			service = s
		}
		p := cookiescan.Port{Port: int(k), Service: service, State: "open", Confidence: conf, Reason: v}
		results.Ports = append(results.Ports, p)
	}
	sort.Sort(results.Ports)

	if args["-j"].(bool) {
		j, _ := json.MarshalIndent(results, "", "    ")
		fmt.Println(string(j))
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
		fmt.Fprintln(w, "Port\tState\tService\tConfidence\tReason")
		for _, p := range results.Ports {
			fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\n", p.Port, p.State, p.Service, p.Confidence, p.Reason)
		}
		w.Flush()
	}
}
