package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	Name        = "public_internet_exporter"
	PingTimeout = 5 * time.Second
)

// Set these at build time, e.g.:
// go build -ldflags "-X main.version=1.2.3 -X main.commit=$(git rev-parse --short HEAD) -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

type PingFunc func(context.Context, netip.Addr) bool

type Exporter struct {
	// Metrics.
	up *prometheus.Desc

	// Depndencies
	ipAddrs []netip.Addr
	ping    PingFunc
}

func NewExporter(ipAddrs []netip.Addr, ping PingFunc) *Exporter {

	for _, ip := range ipAddrs {
		if !ip.Is4() {
			panic(fmt.Errorf("invalid ipv4 address: %v", ip))
		}
	}

	const ns = Name
	return &Exporter{
		up: prometheus.NewDesc(
			prometheus.BuildFQName(ns, "", "up"),
			"Whether internet is accessible (1) or not (0).",
			nil,
			nil,
		),

		ipAddrs: ipAddrs,
		ping:    ping,
	}
}

// Describe is part of prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.up
}

// Collect is called by Prometheus on scrape.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if e.canAccessPublicInternet(ctx) {
		ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, 1)
	} else {
		ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, 0)
	}
}

func (e *Exporter) canAccessPublicInternet(ctx context.Context) (ok bool) {
	pingCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	n := len(e.ipAddrs)
	isAccessible := make(chan bool, n)

	for _, ip := range e.ipAddrs {
		ip := ip
		go func() {
			slog.Debug("ping dns resolver", "ip", ip)
			isAccessible <- e.ping(pingCtx, ip)
		}()
	}

	for i := 0; i < n; i++ {
		select {
		case ok := <-isAccessible:
			// One was successful
			if ok {
				cancel()
				return true
			}

		// All timedout
		case <-ctx.Done():
			return false
		}
	}

	// All failed
	return false
}

func ping(ctx context.Context, ip netip.Addr) bool {
	// Default timeout if ctx has no deadline.

	deadline := time.Now().Add(PingTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := ctx.Err(); err != nil {
		return false
	}

	// Build destination address.
	dst := &net.IPAddr{IP: net.IP(ip.AsSlice())}

	// Open socket depending on v4/v6.
	var (
		c     *icmp.PacketConn
		err   error
		proto int
	)

	// Use raw ICMP for simplicity.
	c, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		panic("need permissions to send icmp requests")
	}
	defer func() {
		if err := c.Close(); err != nil {
			slog.Error("couldn't close icmp socket", "err", err)
		}
	}()

	proto = 1 // ICMP for IPv4

	// Make sure ReadFrom unblocks when ctx is canceled.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if err := c.SetDeadline(time.Now()); err != nil {
				slog.Error("couldn't icmp request deadline upon context cancellation", "err", err)
			}
		case <-done:
		}
	}()
	defer close(done)

	if err := c.SetDeadline(deadline); err != nil {
		panic(fmt.Errorf("couldn't set deadline for icmp request: %w", err))
	}

	id := os.Getpid() & 0xffff
	seq := 1

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	if _, err := c.WriteTo(b, dst); err != nil {
		slog.Debug("couldn't send message to dst", "err", err)
		return false
	}

	// Read until we get our matching reply or we hit deadline/ctx cancel.
	rb := make([]byte, 1500)
	for {
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			slog.Debug("error while reading response", "err", err)
			return false
		}

		rm, err := icmp.ParseMessage(proto, rb[:n])
		if err != nil {

			continue
		}

		if rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		body, ok := rm.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		peerIPAddr, ok := peer.(*net.IPAddr)
		if !ok {
			continue
		}

		if body.ID == id && body.Seq == seq && peerIPAddr.IP.Equal(net.IP(ip.AsSlice())) {
			return true
		}
	}
}

func main() {

	var (
		listenAddr  = flag.String("web.listen-address", ":9100", "Address to listen on for HTTP requests.")
		metricsPath = flag.String("web.metrics-path", "/metrics", "Path under which to expose metrics.")
		showVersion bool
		logLevel    slog.Level
	)

	flag.TextVar(&logLevel, "log.level", slog.LevelInfo, "set log level")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")

	flag.Parse()

	if showVersion {
		fmt.Printf("%s version=%s commit=%s buildDate=%s\n", Name, version, commit, buildDate)
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Use a custom registry so you control exactly what is exported.
	reg := prometheus.NewRegistry()

	// Optional: include Go/runtime/process metrics (common in exporters).
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// Exporter build/info metric.
	buildInfo := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_build_info", Name),
			Help: "Build information about the exporter.",
		},
		[]string{"version", "commit", "build_date"},
	)
	buildInfo.WithLabelValues(version, commit, buildDate).Set(1)

	reg.MustRegister(buildInfo)
	reg.MustRegister(NewExporter([]netip.Addr{
		// TODO: Make this configurable through flags.
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("8.8.4.4"),
		netip.MustParseAddr("1.1.1.1"),
	},
		ping,
	))

	mux := http.NewServeMux()

	// Metrics endpoint.
	mux.Handle(*metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	// Simple health endpoint.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	// Root/info page.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w,
			"%s\n\n"+
				"Endpoints:\n"+
				"  %s  metrics\n"+
				"  /healthz  health\n\n"+
				"Build:\n"+
				"  version=%s commit=%s buildDate=%s\n",
			Name, *metricsPath, version, commit, buildDate,
		)
	})

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting server", "listenAddr", *listenAddr, "metricsPath", *metricsPath)
		errCh <- srv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("shutting down", "signal", sig)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "err", err)
		os.Exit(-1) // TODO: maybe use a proper error code
	}
}
