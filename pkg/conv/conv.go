package conv

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
)

// --- JSON structure types ---

type Log struct {
	Access   string `json:"access"`
	Error    string `json:"error"`
	LogLevel string `json:"loglevel"`
}

type Sniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
	RouteOnly    bool     `json:"routeOnly"`
}

type InboundSettings struct {
	Auth             string `json:"auth"`
	UDP              bool   `json:"udp"`
	AllowTransparent bool   `json:"allowTransparent"`
}

type Inbound struct {
	Tag      string          `json:"tag"`
	Port     int             `json:"port"`
	Listen   string          `json:"listen"`
	Protocol string          `json:"protocol"`
	Sniffing Sniffing        `json:"sniffing"`
	Settings InboundSettings `json:"settings"`
}

type VnextUser struct {
	ID         string `json:"id"`
	AlterID    int    `json:"alterId"`
	Email      string `json:"email"`
	Security   string `json:"security"`
	Encryption string `json:"encryption,omitempty"`
	Flow       string `json:"flow,omitempty"`
}

type Vnext struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []VnextUser `json:"users"`
}

type VnextSettings struct {
	Vnext []Vnext `json:"vnext"`
}

type TrojanServer struct {
	Address  string `json:"address"`
	Method   string `json:"method"`
	OTA      bool   `json:"ota"`
	Password string `json:"password"`
	Port     int    `json:"port"`
	Level    int    `json:"level"`
	Flow     string `json:"flow"`
}

type TrojanSettings struct {
	Servers []TrojanServer `json:"servers"`
}

type RealitySettings struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	Show        bool   `json:"show"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
}

type TLSSettings struct {
	AllowInsecure bool     `json:"allowInsecure"`
	ServerName    string   `json:"serverName"`
	ALPN          []string `json:"alpn"`
	Show          bool     `json:"show"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
}

type WSSettings struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

type TCPHeaderRequest struct {
	Version string              `json:"version"`
	Method  string              `json:"method"`
	Path    []string            `json:"path"`
	Headers map[string][]string `json:"headers"`
}

type TCPHeader struct {
	Type    string            `json:"type"`
	Request *TCPHeaderRequest `json:"request,omitempty"`
}

type TCPSettings struct {
	Header TCPHeader `json:"header"`
}

type GRPCSettings struct {
	ServiceName         string `json:"serviceName"`
	MultiMode           bool   `json:"multiMode"`
	IdleTimeout         int    `json:"idle_timeout"`
	HealthCheckTimeout  int    `json:"health_check_timeout"`
	PermitWithoutStream bool   `json:"permit_without_stream"`
	InitialWindowsSize  int    `json:"initial_windows_size"`
}

type StreamSettings struct {
	Network         string           `json:"network"`
	Security        string           `json:"security,omitempty"`
	RealitySettings *RealitySettings `json:"realitySettings,omitempty"`
	TLSSettings     *TLSSettings     `json:"tlsSettings,omitempty"`
	WSSettings      *WSSettings      `json:"wsSettings,omitempty"`
	TCPSettings     *TCPSettings     `json:"tcpSettings,omitempty"`
	GRPCSettings    *GRPCSettings    `json:"grpcSettings,omitempty"`
}

type Mux struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"`
}

type BlackholeResponse struct {
	Type string `json:"type"`
}

type BlackholeSettings struct {
	Response BlackholeResponse `json:"response"`
}

type Outbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	Mux            *Mux            `json:"mux,omitempty"`
}

// Config matches Python's output order: log, outbounds, inbounds
type Config struct {
	Log       Log        `json:"log"`
	Outbounds []Outbound `json:"outbounds"`
	Inbounds  []Inbound  `json:"inbounds"`
}

// --- Helper functions ---

func randomHex(n int) string {
	const hexChars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexChars[rand.Intn(len(hexChars))]
	}
	return string(b)
}

func splitter(uri, target string) string {
	parts := strings.SplitN(uri, target, 2)
	if len(parts) < 2 {
		return ""
	}
	remainder := parts[1]
	if idx := strings.Index(remainder, "&"); idx != -1 {
		return remainder[:idx]
	}
	if idx := strings.Index(remainder, "#"); idx != -1 {
		return remainder[:idx]
	}
	return remainder
}

func generateInbounds(host string, port, socksPort int) []Inbound {
	sniff := Sniffing{
		Enabled:      true,
		DestOverride: []string{"http", "tls"},
		RouteOnly:    false,
	}
	settings := InboundSettings{
		Auth:             "noauth",
		UDP:              true,
		AllowTransparent: false,
	}
	return []Inbound{
		{Tag: "socks", Port: socksPort, Listen: host, Protocol: "socks", Sniffing: sniff, Settings: settings},
		{Tag: "http", Port: port, Listen: host, Protocol: "http", Sniffing: sniff, Settings: settings},
	}
}

func jsonMaker(config *Config) (string, error) {

	data, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	return string(data), nil
}

func marshalRaw(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func directOutbound() Outbound {
	return Outbound{
		Tag:      "direct",
		Protocol: "freedom",
		Settings: marshalRaw(struct{}{}),
	}
}

func blockOutbound() Outbound {
	return Outbound{
		Tag:      "block",
		Protocol: "blackhole",
		Settings: marshalRaw(BlackholeSettings{Response: BlackholeResponse{Type: "http"}}),
	}
}

func newTCPSettings(hostHTTP, headerType string, path []string) *TCPSettings {
	return &TCPSettings{
		Header: TCPHeader{
			Type: headerType,
			Request: &TCPHeaderRequest{
				Version: "1.1",
				Method:  "GET",
				Path:    path,
				Headers: map[string][]string{
					"Host":            {hostHTTP},
					"User-Agent":      {""},
					"Accept-Encoding": {"gzip, deflate"},
					"Connection":      {"keep-alive"},
					"Pragma":          {"no-cache"},
				},
			},
		},
	}
}

func newGRPCSettings(serviceName string) *GRPCSettings {
	return &GRPCSettings{
		ServiceName:         serviceName,
		MultiMode:           false,
		IdleTimeout:         60,
		HealthCheckTimeout:  20,
		PermitWithoutStream: false,
		InitialWindowsSize:  0,
	}
}

func parseALPN(alpnStr string) []string {
	var alpn []string
	if strings.Contains(alpnStr, "http/1.1") {
		alpn = append(alpn, "http/1.1")
	}
	if strings.Contains(alpnStr, "h2") {
		alpn = append(alpn, "h2")
	}
	if strings.Contains(alpnStr, "h3") {
		alpn = append(alpn, "h3")
	}
	return alpn
}

func decodePercent(uri string) string {
	decoded, err := url.QueryUnescape(uri)
	if err != nil {
		return strings.ReplaceAll(uri, "%2F", "/")
	}
	return decoded
}

func applyTCPHeaderFromURI(uri string, ss *StreamSettings) {
	if !strings.Contains(uri, "host=") {
		return
	}
	hostHTTP := splitter(uri, "host=")
	headerType := "http"
	if strings.Contains(uri, "headertype") {
		headerType = splitter(uri, "headertype=")
	}
	path := []string{"/"}
	if strings.Contains(uri, "path=") {
		path = []string{splitter(uri, "path=")}
	}
	ss.TCPSettings = newTCPSettings(hostHTTP, headerType, path)
}

func applyGRPCFromURI(uri string, ss *StreamSettings) {
	if ss.Network != "grpc" {
		return
	}
	serviceName := ""
	if strings.Contains(uri, "serviceName=") {
		serviceName = splitter(uri, "serviceName=")
	}
	ss.GRPCSettings = newGRPCSettings(serviceName)
}

func applyTLSFromURI(uri string, ss *StreamSettings) {
	if !strings.Contains(uri, "security=") {
		return
	}
	security := splitter(uri, "security=")
	if security == "none" {
		return
	}
	ss.Security = security
	tls := &TLSSettings{
		AllowInsecure: true,
		Show:          false,
	}
	if strings.Contains(uri, "sni=") {
		tls.ServerName = splitter(uri, "sni=")
	}
	if strings.Contains(uri, "alpn=") {
		tls.ALPN = parseALPN(splitter(uri, "alpn="))
	}
	if strings.Contains(uri, "fp=") {
		fp := splitter(uri, "fp=")
		if fp != "none" {
			tls.Fingerprint = fp
		}
	}
	ss.TLSSettings = tls
}

// --- URI parsing ---

func parseVlessURI(uri string) (protocol, uid, address string, port int, network string) {
	protocol = strings.SplitN(uri, "://", 2)[0]
	afterScheme := strings.SplitN(uri, "//", 2)[1]
	uid = strings.SplitN(afterScheme, "@", 2)[0]
	afterAt := strings.SplitN(afterScheme, "@", 2)[1]
	address = strings.SplitN(afterAt, ":", 2)[0]
	portStr := strings.SplitN(afterAt, ":", 2)[1]
	portStr = strings.SplitN(portStr, "?", 2)[0]
	port, _ = strconv.Atoi(portStr)
	network = splitter(uri, "type=")
	return
}

func parseTrojanURI(uri string) (protocol, password, address string, port int, network string) {
	protocol = strings.SplitN(uri, "://", 2)[0]
	afterScheme := strings.SplitN(uri, "//", 2)[1]
	password = strings.SplitN(afterScheme, "@", 2)[0]
	afterAt := strings.SplitN(afterScheme, "@", 2)[1]
	address = strings.SplitN(afterAt, ":", 2)[0]
	portStr := strings.SplitN(afterAt, ":", 2)[1]
	portStr = strings.SplitN(portStr, "?", 2)[0]
	port, _ = strconv.Atoi(portStr)
	network = splitter(uri, "type=")
	return
}

// --- VMess base64 decoded ---

type VmessDecoded struct {
	ID   string `json:"id"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	Net  string `json:"net"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	FP   string `json:"fp"`
	Type string `json:"type"`
}

func (v *VmessDecoded) PortInt() int {
	switch p := v.Port.(type) {
	case float64:
		return int(p)
	case string:
		n, _ := strconv.Atoi(p)
		return n
	}
	return 0
}

func decodeVmess(uri string) (*VmessDecoded, error) {
	encoded := strings.SplitN(uri, "://", 2)[1]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed: %w", err)
		}
	}
	var v VmessDecoded
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %w", err)
	}
	return &v, nil
}

// --- Outbound builders ---

func vnextProxyOutbound(protocol, address string, port int, user VnextUser, ss *StreamSettings) Outbound {
	settings := VnextSettings{
		Vnext: []Vnext{{Address: address, Port: port, Users: []VnextUser{user}}},
	}
	return Outbound{
		Tag:            "proxy",
		Protocol:       protocol,
		Settings:       marshalRaw(settings),
		StreamSettings: ss,
		Mux:            &Mux{Enabled: false, Concurrency: -1},
	}
}

func trojanProxyOutbound(protocol, address, password string, port int, ss *StreamSettings) Outbound {
	settings := TrojanSettings{
		Servers: []TrojanServer{{
			Address:  address,
			Method:   "chacha20",
			OTA:      false,
			Password: password,
			Port:     port,
			Level:    1,
			Flow:     "",
		}},
	}
	return Outbound{
		Tag:            "proxy",
		Protocol:       protocol,
		Settings:       marshalRaw(settings),
		StreamSettings: ss,
		Mux:            &Mux{Enabled: false, Concurrency: -1},
	}
}

// --- Converter functions ---

func convertURIRealityJSON(host string, port, socksPort int, uri string) (string, error) {
	protocol, uid, address, destPort, network := parseVlessURI(uri)
	security := splitter(uri, "security=")
	sni := splitter(uri, "sni=")
	fp := splitter(uri, "fp=")
	pbk := splitter(uri, "pbk=")
	sid := ""
	if strings.Contains(uri, "sid=") {
		sid = splitter(uri, "sid=")
	}
	spx := ""
	if strings.Contains(uri, "spx=") {
		spx = splitter(uri, "spx=")
	}
	flow := ""
	if strings.Contains(uri, "flow") {
		flow = splitter(uri, "flow=")
	}

	ss := &StreamSettings{
		Network:  network,
		Security: security,
		RealitySettings: &RealitySettings{
			ServerName: sni, Fingerprint: fp, Show: false,
			PublicKey: pbk, ShortID: sid, SpiderX: spx,
		},
	}

	user := VnextUser{ID: uid, AlterID: 0, Email: "t@t.tt", Security: "auto", Encryption: "none", Flow: flow}

	applyTCPHeaderFromURI(uri, ss)
	applyGRPCFromURI(uri, ss)

	config := &Config{
		Log:       Log{LogLevel: "warning"},
		Outbounds: []Outbound{vnextProxyOutbound(protocol, address, destPort, user, ss), directOutbound(), blockOutbound()},
		Inbounds:  generateInbounds(host, port, socksPort),
	}
	return jsonMaker(config)
}

func convertURIVlessWsJSON(host string, port, socksPort int, uri string) (string, error) {
	protocol, uid, address, destPort, network := parseVlessURI(uri)

	headers := map[string]string{}
	if strings.Contains(uri, "host=") {
		headers["Host"] = splitter(uri, "host=")
	}
	path := "/"
	if strings.Contains(uri, "path=") {
		path = splitter(uri, "path=")
	}

	ss := &StreamSettings{
		Network:    network,
		WSSettings: &WSSettings{Path: path, Headers: headers},
	}
	applyTLSFromURI(uri, ss)

	user := VnextUser{ID: uid, AlterID: 0, Email: "t@t.tt", Security: "auto", Encryption: "none", Flow: ""}

	config := &Config{
		Log:       Log{LogLevel: "warning"},
		Outbounds: []Outbound{vnextProxyOutbound(protocol, address, destPort, user, ss), directOutbound(), blockOutbound()},
		Inbounds:  generateInbounds(host, port, socksPort),
	}
	return jsonMaker(config)
}

func convertURIVlessTcpJSON(host string, port, socksPort int, uri string) (string, error) {
	protocol, uid, address, destPort, network := parseVlessURI(uri)

	ss := &StreamSettings{Network: network}

	applyTCPHeaderFromURI(uri, ss)
	applyTLSFromURI(uri, ss)
	applyGRPCFromURI(uri, ss)

	user := VnextUser{ID: uid, AlterID: 0, Email: "t@t.tt", Security: "auto", Encryption: "none", Flow: ""}

	config := &Config{
		Log:       Log{LogLevel: "warning"},
		Outbounds: []Outbound{vnextProxyOutbound(protocol, address, destPort, user, ss), directOutbound(), blockOutbound()},
		Inbounds:  generateInbounds(host, port, socksPort),
	}
	return jsonMaker(config)
}

func convertURIVmessWsJSON(host string, port, socksPort int, uri string) (string, error) {
	decoded, err := decodeVmess(uri)
	if err != nil {
		return "", err
	}

	protocol := strings.SplitN(uri, "://", 2)[0]
	headers := map[string]string{}
	if decoded.Host != "" {
		headers["Host"] = decoded.Host
	}
	path := "/"
	if decoded.Path != "" {
		path = decoded.Path
	}

	ss := &StreamSettings{
		Network:    decoded.Net,
		WSSettings: &WSSettings{Path: path, Headers: headers},
	}

	if decoded.TLS != "" && strings.ToLower(decoded.TLS) != "none" {
		ss.Security = strings.ToLower(decoded.TLS)
		tls := &TLSSettings{AllowInsecure: true, ServerName: decoded.SNI, Show: false}
		if decoded.ALPN != "" {
			tls.ALPN = parseALPN(decoded.ALPN)
		}
		if decoded.FP != "" && decoded.FP != "none" {
			tls.Fingerprint = decoded.FP
		}
		ss.TLSSettings = tls
	}

	user := VnextUser{ID: decoded.ID, AlterID: 0, Email: "t@t.tt", Security: "auto"}

	config := &Config{
		Log:       Log{LogLevel: "warning"},
		Outbounds: []Outbound{vnextProxyOutbound(protocol, decoded.Add, decoded.PortInt(), user, ss), directOutbound(), blockOutbound()},
		Inbounds:  generateInbounds(host, port, socksPort),
	}
	return jsonMaker(config)
}

func convertURIVmessTcpJSON(host string, port, socksPort int, uri string) (string, error) {
	decoded, err := decodeVmess(uri)
	if err != nil {
		return "", err
	}

	protocol := strings.SplitN(uri, "://", 2)[0]
	ss := &StreamSettings{Network: decoded.Net}

	if decoded.Host != "" {
		headerType := "http"
		if decoded.Type != "" {
			headerType = decoded.Type
		}
		path := []string{"/"}
		if decoded.Path != "" {
			path = []string{decoded.Path}
		}
		ss.TCPSettings = newTCPSettings(decoded.Host, headerType, path)
	}

	if decoded.TLS != "" && strings.ToLower(decoded.TLS) != "none" && decoded.TLS != "" {
		ss.Security = strings.ToLower(decoded.TLS)
		tls := &TLSSettings{AllowInsecure: true, ServerName: decoded.SNI, Show: false}
		if decoded.ALPN != "" {
			tls.ALPN = parseALPN(decoded.ALPN)
		}
		if decoded.FP != "" && decoded.FP != "none" {
			tls.Fingerprint = decoded.FP
		}
		ss.TLSSettings = tls
	}

	if decoded.Net == "grpc" {
		serviceName := ""
		if decoded.Path != "" {
			serviceName = decoded.Path
		}
		ss.GRPCSettings = newGRPCSettings(serviceName)
	}

	user := VnextUser{ID: decoded.ID, AlterID: 0, Email: "t@t.tt", Security: "auto"}

	config := &Config{
		Log:       Log{LogLevel: "warning"},
		Outbounds: []Outbound{vnextProxyOutbound(protocol, decoded.Add, decoded.PortInt(), user, ss), directOutbound(), blockOutbound()},
		Inbounds:  generateInbounds(host, port, socksPort),
	}
	return jsonMaker(config)
}

func convertURITrojanRealityJSON(host string, port, socksPort int, uri string) (string, error) {
	protocol, password, address, destPort, network := parseTrojanURI(uri)
	security := splitter(uri, "security=")
	sni := splitter(uri, "sni=")
	fp := splitter(uri, "fp=")
	pbk := splitter(uri, "pbk=")
	sid := ""
	if strings.Contains(uri, "sid=") {
		sid = splitter(uri, "sid=")
	}
	spx := ""
	if strings.Contains(uri, "spx=") {
		spx = splitter(uri, "spx=")
	}

	ss := &StreamSettings{
		Network:  network,
		Security: security,
		RealitySettings: &RealitySettings{
			ServerName: sni, Fingerprint: fp, Show: false,
			PublicKey: pbk, ShortID: sid, SpiderX: spx,
		},
	}

	applyTCPHeaderFromURI(uri, ss)
	applyGRPCFromURI(uri, ss)

	config := &Config{
		Log:       Log{LogLevel: "warning"},
		Outbounds: []Outbound{trojanProxyOutbound(protocol, address, password, destPort, ss), directOutbound(), blockOutbound()},
		Inbounds:  generateInbounds(host, port, socksPort),
	}
	return jsonMaker(config)
}

func convertURITrojanWsJSON(host string, port, socksPort int, uri string) (string, error) {
	protocol, password, address, destPort, network := parseTrojanURI(uri)

	headers := map[string]string{}
	if strings.Contains(uri, "host=") {
		headers["Host"] = splitter(uri, "host=")
	}
	path := "/"
	if strings.Contains(uri, "path=") {
		path = splitter(uri, "path=")
	}

	ss := &StreamSettings{
		Network:    network,
		WSSettings: &WSSettings{Path: path, Headers: headers},
	}
	applyTLSFromURI(uri, ss)

	config := &Config{
		Log:       Log{LogLevel: "warning"},
		Outbounds: []Outbound{trojanProxyOutbound(protocol, address, password, destPort, ss), directOutbound(), blockOutbound()},
		Inbounds:  generateInbounds(host, port, socksPort),
	}
	return jsonMaker(config)
}

func convertURITrojanTcpJSON(host string, port, socksPort int, uri string) (string, error) {
	protocol, password, address, destPort, network := parseTrojanURI(uri)

	ss := &StreamSettings{Network: network}

	applyTCPHeaderFromURI(uri, ss)
	applyTLSFromURI(uri, ss)
	applyGRPCFromURI(uri, ss)

	config := &Config{
		Log:       Log{LogLevel: "warning"},
		Outbounds: []Outbound{trojanProxyOutbound(protocol, address, password, destPort, ss), directOutbound(), blockOutbound()},
		Inbounds:  generateInbounds(host, port, socksPort),
	}
	return jsonMaker(config)
}

// --- Checker functions ---

func vlessRealityChecker(uri string) bool {
	return strings.Contains(uri, "vless://") &&
		strings.Contains(uri, "security=") &&
		splitter(uri, "security=") == "reality"
}

func vlessWsChecker(uri string) bool {
	return strings.Contains(uri, "vless://") && strings.Contains(uri, "type=ws")
}

func vlessTcpChecker(uri string) bool {
	return strings.Contains(uri, "vless://") &&
		(strings.Contains(uri, "type=tcp") || strings.Contains(uri, "type=grpc"))
}

func vmessWsChecker(uri string) bool {
	if !strings.Contains(uri, "vmess://") {
		return false
	}
	decoded, err := decodeVmess(uri)
	if err != nil {
		return false
	}
	return decoded.Net == "ws"
}

func vmessTcpChecker(uri string) bool {
	if !strings.Contains(uri, "vmess://") {
		return false
	}
	decoded, err := decodeVmess(uri)
	if err != nil {
		return false
	}
	return decoded.Net == "tcp" || decoded.Net == "grpc"
}

func trojanRealityChecker(uri string) bool {
	return strings.Contains(uri, "trojan://") &&
		strings.Contains(uri, "security=") &&
		splitter(uri, "security=") == "reality"
}

func trojanWsChecker(uri string) bool {
	return strings.Contains(uri, "trojan://") && strings.Contains(uri, "type=ws")
}

func trojanTcpChecker(uri string) bool {
	return strings.Contains(uri, "trojan://") &&
		(strings.Contains(uri, "type=tcp") || strings.Contains(uri, "type=grpc"))
}

// --- Main entry point ---

func ConvertURIJSON(host string, port, socksPort int, uri string) (string, error) {
	if uri == "" {
		return "", fmt.Errorf("uri is empty")
	}

	// Decode percent-encoded characters before parsing
	uri = decodePercent(uri)

	switch {
	case vlessRealityChecker(uri):
		return convertURIRealityJSON(host, port, socksPort, uri)
	case vlessWsChecker(uri):
		return convertURIVlessWsJSON(host, port, socksPort, uri)
	case vlessTcpChecker(uri):
		return convertURIVlessTcpJSON(host, port, socksPort, uri)
	case vmessWsChecker(uri):
		return convertURIVmessWsJSON(host, port, socksPort, uri)
	case vmessTcpChecker(uri):
		return convertURIVmessTcpJSON(host, port, socksPort, uri)
	case trojanRealityChecker(uri):
		return convertURITrojanRealityJSON(host, port, socksPort, uri)
	case trojanWsChecker(uri):
		return convertURITrojanWsJSON(host, port, socksPort, uri)
	case trojanTcpChecker(uri):
		return convertURITrojanTcpJSON(host, port, socksPort, uri)
	default:
		return "", fmt.Errorf("unsupported URI format")
	}
}
