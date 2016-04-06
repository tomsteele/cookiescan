package cookiescan

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
)

// Reads '/etc/services' and creates a port[service] lookup table
func buildServices() (map[int]string, error) {
	services := make(map[int]string)
	f, err := os.Open("/etc/services")
	if err != nil {
		return services, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	re := regexp.MustCompile("([^\\s]+)\\s+([0-9]+)/(tcp)")
	for scanner.Scan() {
		result := re.FindStringSubmatch(scanner.Text())
		if len(result) == 4 {
			port, err := strconv.Atoi(result[2])
			if err != nil {
				continue
			}
			services[port] = result[1]
		}
	}
	if err := scanner.Err(); err != nil {
		return services, err
	}
	return services, nil
}
