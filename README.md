cookiescan
==========

TCP port scanning through SYN flood protected networks

## Download
Binary packages for Linux and OS X are available [here](http://github.com/tomsteele/cookiescan/releases/latest). If you need to build for another operating system see the go documentation or get in contact with me and I'll see what I can do.

## Install
After installing libpcap-dev:
```
$ unzip cookiescan*.zip
$ ./cookiescan
```

## Usage
```
$ cookiescan -h

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
```
