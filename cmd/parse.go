package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/miekg/pcap"
)

const usage = `

Usage:
  cookiescan [options] <target>
  cookiescan -h | --help
  cookiescan -v | --version

Required Arguments:
  target:           IP Address, Hostname, or CIDR network. May also be a a newline separated
                    file containing targets.

Options:
  -h --help         Show this message.
  -v --version      Show version.
  -p <port ranges>  Ports to scan. Ex: -p 22; -p 1-65535, -p 80,443. [default: 1-1024]
  -e <port ranges>  Ports to exclude from scan. Ex: -e 22; -p 21,23. [default: 0]
  -g <int>          Amount of goroutines to spread connection attempts across. [default: 1000]
  -c <int>          Minimum confidence level to flag port as open. [default: 1]
  -i <interface>    Network interface to listen on.
  -t <timeout>      Timeout in Milliseconds to wait for a connection. [default: 400]
  -j <file>         Output JSON to file.

`

type O struct {
	services       []int
	minconfidence  int
	minconcurrency int
	timeout        time.Duration
	device         string
	ips            []string
	jsonfile       string
}

func parse() *O {
	args, err := docopt.Parse(usage, nil, true, "cookiescan 2.1.0", false)
	if err != nil {
		log.Fatalf("Error parsing usage. Error: %s\n", err.Error())
	}
	if err != nil {
		log.Fatalf("Error parsing usage. Error: %s\n", err.Error())
	}
	o := &O{}

	if jsonfile, ok := args["-j"].(string); ok {
		o.jsonfile = jsonfile
	}

	var lines []string
	hostorfile := args["<target>"].(string)
	if ok, err := os.Stat(hostorfile); err == nil && ok != nil {
		if lines, err = readFileLines(hostorfile); err != nil {
			log.Fatalf("Error parsing input file. Error: %s\n", err.Error())
		}
	} else {
		lines = append(lines, hostorfile)
	}

	if o.ips, err = linesToIPList(lines); err != nil {
		log.Fatalf("Error parsing targets. Error: %s\n", err.Error())
	}

	if o.services, err = explode(args["-p"].(string)); err != nil {
		log.Fatalf("Error parsing port string. Error %s\n", err.Error())
	}
	servicesToExclude, err := explode(args["-e"].(string))
	if err != nil && args["-e"].(string) != "0" {
		log.Fatalf("Error parsing exclude port string. Error %s\n", err.Error())
	}
	for _, e := range servicesToExclude {
		for i, s := range o.services {
			if e == s {
				if len(o.services) <= 1 {
					log.Fatal("Error parsing exlude port range. Resulting port list leaves no ports to scan")
				}
				o.services = append(o.services[:i], o.services[i+1:]...)
			}
		}
	}

	if o.minconfidence, err = strconv.Atoi(args["-c"].(string)); err != nil {
		log.Fatal("Invalid argument for -c.")
	}
	if o.minconcurrency, err = strconv.Atoi(args["-g"].(string)); err != nil {
		log.Fatal("Invalid argument for -g.")
	}

	ti, err := strconv.Atoi(args["-t"].(string))
	if err != nil {
		log.Fatal("Invalid argument for -t.")
	}
	o.timeout = time.Duration(ti) * time.Millisecond

	if args["-i"] != nil {
		o.device = args["-i"].(string)
	}
	if o.device == "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal("Error finding interfaces. Error: ", err)
		}
		if len(devs) == 0 {
			log.Fatal("No interfaces found. Are you not running as root?")
		}
		o.device = devs[0].Name
	}

	return o
}

// linesToIPList processes a list of IP addresses or networks in CIDR format.
// Returning a list of all possible IP addresses.
func linesToIPList(lines []string) ([]string, error) {
	ipList := []string{}
	for _, line := range lines {
		if net.ParseIP(line) != nil {
			ipList = append(ipList, line)
		} else if ip, network, err := net.ParseCIDR(line); err == nil {
			for ip := ip.Mask(network.Mask); network.Contains(ip); increaseIP(ip) {
				ipList = append(ipList, ip.String())
			}
		} else {
			return ipList, fmt.Errorf("%s is not an IP Address or CIDR Network", line)
			ips, err := net.LookupIP(line)
			if err != nil {
				return ipList, fmt.Errorf("%s is not a valid hostname", line)
			}
			ipList = append(ipList, ips[0].String())
		}
	}
	return ipList, nil
}

// increases an IP by a single address.
func increaseIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// readFileLines returns all the lines in a file.
func readFileLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	lines := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
