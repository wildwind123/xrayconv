package conv

import (
	"testing"
)

func TestConv(t *testing.T) {
	host := "127.0.0.1"
	port := 10809
	socksPort := 10808
	url := "trojan://HsQONAL727@host.org:21532?type=tcp&security=reality&pbk=p7R9bWo5SA5-tGN0Q5fpE1_qCUh80RyNjHoC1cBZKwc&fp=chrome&sni=cloud.mail.ru&sid=e6fbc395f5ab69&spx=%2F#Finland-vpnsafe2"
	r, err := ConvertURIJSON(host, port, socksPort, url)

	if err != nil {
		t.Fatal(err)
	}
	if r != `{"log":{"access":"","error":"","loglevel":"warning"},"outbounds":[{"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":"host.org","method":"chacha20","ota":false,"password":"HsQONAL727","port":21532,"level":1,"flow":""}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"cloud.mail.ru","fingerprint":"chrome","show":false,"publicKey":"p7R9bWo5SA5-tGN0Q5fpE1_qCUh80RyNjHoC1cBZKwc","shortId":"e6fbc395f5ab69","spiderX":"/"}},"mux":{"enabled":false,"concurrency":-1}},{"tag":"direct","protocol":"freedom","settings":{}},{"tag":"block","protocol":"blackhole","settings":{"response":{"type":"http"}}}],"inbounds":[{"tag":"socks","port":10808,"listen":"127.0.0.1","protocol":"socks","sniffing":{"enabled":true,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":true,"allowTransparent":false}},{"tag":"http","port":10809,"listen":"127.0.0.1","protocol":"http","sniffing":{"enabled":true,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":true,"allowTransparent":false}}]}` {
		t.Fatal("unexpected result")
	}
}
