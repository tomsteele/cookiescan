package main

import (
	"errors"
	"strconv"
	"strings"
)

// Turns a string of ports separated by '-' or ',' and returns a slice of Ints.
func explode(s string) ([]int, error) {
	const errmsg = "Invalid port specification"
	ports := []int{}
	switch {
	case strings.Contains(s, "-"):
		sp := strings.Split(s, "-")
		if len(sp) != 2 {
			return ports, errors.New(errmsg)
		}
		start, err := strconv.Atoi(sp[0])
		if err != nil {
			return ports, errors.New(errmsg)
		}
		end, err := strconv.Atoi(sp[1])
		if err != nil {
			return ports, errors.New(errmsg)
		}
		if start > end || start < 1 || end > 65535 {
			return ports, errors.New(errmsg)
		}
		for ; start <= end; start++ {
			ports = append(ports, start)
		}
	case strings.Contains(s, ","):
		sp := strings.Split(s, ",")
		for _, p := range sp {
			i, err := strconv.Atoi(p)
			if err != nil {
				return ports, errors.New(errmsg)
			}
			if i < 1 || i > 65535 {
				return ports, errors.New(errmsg)
			}
			ports = append(ports, i)
		}
	default:
		i, err := strconv.Atoi(s)
		if err != nil {
			return ports, errors.New(errmsg)
		}
		if i < 1 || i > 65535 {
			return ports, errors.New(errmsg)
		}
		ports = append(ports, i)
	}
	return ports, nil
}
