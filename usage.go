package main

const usage = `

Usage:
  cookiescan [options] <target>
  cookiescan -h | --help
  cookiescan -v | --version
 
Required Arguments:
  target:           IP Address or Hostname

Options:
  -h --help         Show this message.
  -v --version      Show version.
  -p <port ranges>  Ex: -p 22; -p 1-65535, -p 80,443. [default: 1-1024]
  -g <int>          Amount of goroutines to spread connection attempts across. [default: 1000]
  -c <int>          Minimum confidence level to flag port as open. [default: 1]
  -i <interface>    Network interface to listen on.
  -t <timeout>      Timeout in Milliseconds to wait for a connection. [default: 400]
  -j                Output JSON.

`
