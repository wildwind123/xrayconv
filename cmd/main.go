package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/wildwind123/xrayconv/pkg/conv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: converter <uri> [host] [port] [socksport]")
		os.Exit(1)
	}

	uri := os.Args[1]
	host := "127.0.0.1"
	port := 10809
	socksPort := 10808

	if len(os.Args) > 2 {
		host = os.Args[2]
	}
	if len(os.Args) > 3 {
		port, _ = strconv.Atoi(os.Args[3])
	}
	if len(os.Args) > 4 {
		socksPort, _ = strconv.Atoi(os.Args[4])
	}

	res, err := conv.ConvertURIJSON(host, port, socksPort, uri)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(res)
}
