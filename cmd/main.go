package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/gosuri/uiprogress"
	"github.com/miekg/pcap"
	"github.com/tomsteele/cookiescan"
)

type empty struct{}
type task struct {
	ip   string
	port int
}

func main() {
	var (
		options = parse()
		filter  = "tcp[13] == 0x11 or tcp[13] == 0x10 or tcp[13] == 0x18"
	)

	h, err := pcap.OpenLive(options.device, int32(320), true, 500)
	if err != nil {
		log.Fatal(err.Error())
	}
	if err = h.SetFilter(filter); err != nil {
		log.Fatal(err.Error())
	}
	db := cookiescan.NewStore(options.ips)

	var (
		track = make(chan empty)
		tasks = make(chan task, options.minconcurrency)
	)

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
				if len(pkt.Headers) < 2 {
					continue
				}
				iphdr, ok := pkt.Headers[0].(*pcap.Iphdr)
				if !ok {
					continue
				}
				if len(iphdr.SrcIp) < 4 {
					continue
				}
				ip := fmt.Sprintf("%v.%v.%v.%v", iphdr.SrcIp[0], iphdr.SrcIp[1], iphdr.SrcIp[2], iphdr.SrcIp[3])
				tcphdr, ok := pkt.Headers[1].(*pcap.Tcphdr)
				if !ok {
					continue
				}
				db.Add(ip, int(tcphdr.SrcPort), tcphdr.FlagsString())
			}
		}
		h.Close()
	}()

	for i := 0; i < options.minconcurrency; i++ {
		go func() {
			for tsk := range tasks {
				c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", tsk.ip, tsk.port), options.timeout)
				if err != nil {
					continue
				}
				c.Close()
			}
		}()
	}

	uiprogress.Start()
	bar := uiprogress.AddBar(len(options.ips) * len(options.services))
	bar.AppendCompleted()
	bar.PrependElapsed()

	for _, ip := range options.ips {
		for _, p := range options.services {
			tasks <- task{ip, p}
			bar.Incr()
		}
	}

	close(tasks)
	time.Sleep(time.Duration(2 * time.Second))
	track <- empty{}
	close(track)
	uiprogress.Stop()

	if options.jsonfile != "" {
		db.JSON(options.minconfidence, options.jsonfile)
	}
	db.Tabbed(options.minconfidence)
}
