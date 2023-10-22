package wsp

import (
	"net/http"
	"testing"

	"github.com/gowsp/wsp/pkg/client"
	"github.com/gowsp/wsp/pkg/logger"
	"github.com/gowsp/wsp/pkg/server"
)

func init() {
	// c := logger.Config{Level: "debug", Output: "d:/tmp/out.txt"}
	c := logger.Config{Level: "debug",}
	c.Init()
}
func TestServer(t *testing.T) {
	wsps := server.New(&server.Config{Auth: "auth", Path: "/proxy"})
	http.ListenAndServe(":8080", wsps)
}
func TestProxyClient(t *testing.T) {
	client := client.New(client.WspcConfig{
		Auth:   "auth",
		Server: "ws://127.0.0.1:8080/proxy",
		Dynamic: []string{
			"socks5://:1080",
			"http://:8088",
		},
	})
	client.ListenAndServe()
}
func TestTunnel(t *testing.T) {
	go client.New(client.WspcConfig{
		Auth:   "auth",
		Server: "ws://127.0.0.1:8080/proxy",
		Remote: []string{
			"tunnel://dynamic:vpn@",
		},
	}).ListenAndServe()
	client.New(client.WspcConfig{
		Auth:   "auth",
		Server: "ws://127.0.0.1:8080/proxy",
		Dynamic: []string{
			"socks5://home:vpn@:8020",
		},
	}).ListenAndServe()
}
func TestReverseProxy(t *testing.T) {
	server := http.NewServeMux()
	server.HandleFunc("/api/users", func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(r.RequestURI))
	})
	server.HandleFunc("/api/groups", func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(r.RequestURI))
	})
	web := http.Server{Handler: server, Addr: ":8010"}
	go web.ListenAndServe()
	// http://127.0.0.1:8010/api/users
	// http://127.0.0.1:8010/api/groups
	client := client.New(client.WspcConfig{
		Auth:   "auth",
		Server: "ws://127.0.0.1:8080/proxy",
		Remote: []string{
			"http://127.0.0.1:8010?mode=path&value=local",
			"http://127.0.0.1:8010/api/?mode=path&value=wuzk",
		},
	})
	// http://127.0.0.1:8080/local/api/users
	// http://127.0.0.1:8080/local/api/groups
	// http://127.0.0.1:8080/wuzk/users
	// http://127.0.0.1:8080/wuzk/groups
	client.ListenAndServe()
}
func TestTCPOverWs(t *testing.T) {
	client.New(client.WspcConfig{
		Auth:   "auth",
		Server: "ws://127.0.0.1:8080/proxy",
		Remote: []string{
			"tcp://127.0.0.1:5900?mode=path&value=test",
		},
	}).ListenAndServe()
}

func TestTunnel1(t *testing.T) {
	client.New(client.WspcConfig{
		Auth:   "auth",
		Server: "ws://127.0.0.1:8080/proxy",
		Remote: []string{
			"tcp://ssh:pwd@192.168.7.171:22",
		},
	}).ListenAndServe()
}
func TestTunnel2(t *testing.T) {
	client.New(client.WspcConfig{
		Auth:   "auth",
		Server: "ws://127.0.0.1:8080/proxy",
		Local: []string{
			"tcp://ssh:pwd@127.0.0.1:2202",
		},
	}).ListenAndServe()
}
