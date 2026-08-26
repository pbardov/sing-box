//go:build with_naive_outbound

package naivexhttp

import (
	"bytes"
	"context"
	stdTLS "crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/cronet-go"
	_ "github.com/sagernet/cronet-go/all"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.NaiveXHTTPOutboundOptions](registry, C.TypeNaiveXHTTP, NewOutbound)
}

var _ adapter.OutboundWithMultiplex = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx                 context.Context
	logger              logger.ContextLogger
	client              *cronet.NaiveClient
	executor            cronet.Executor
	roundTripper        *cronet.RoundTripper
	httpClient          *http.Client
	httpTransport       *http.Transport
	http1Access         chan struct{}
	uotClient           *uot.Client
	multiplexDialer     *mux.Client
	baseURL             url.URL
	extraHeaders        map[string]string
	authorization       string
	maxUploadSize       int
	postInterval        time.Duration
	uploadCoalesceBytes int
	uploadCoalesceDelay time.Duration
	maxConcurrentPosts  int
	quic                bool
	http1               bool
	postAccess          chan struct{}
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveXHTTPOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if options.TLS.DisableSNI {
		return nil, E.New("disable_sni is not supported on naive-xhttp outbound")
	}
	if options.TLS.Insecure {
		return nil, E.New("insecure is not supported on naive-xhttp outbound")
	}
	if len(options.TLS.ALPN) > 0 {
		return nil, E.New("alpn is not supported on naive-xhttp outbound")
	}
	if options.TLS.MinVersion != "" {
		return nil, E.New("min_version is not supported on naive-xhttp outbound")
	}
	if options.TLS.MaxVersion != "" {
		return nil, E.New("max_version is not supported on naive-xhttp outbound")
	}
	if len(options.TLS.CipherSuites) > 0 {
		return nil, E.New("cipher_suites is not supported on naive-xhttp outbound")
	}
	if len(options.TLS.CurvePreferences) > 0 {
		return nil, E.New("curve_preferences is not supported on naive-xhttp outbound")
	}
	if len(options.TLS.ClientCertificate) > 0 || options.TLS.ClientCertificatePath != "" {
		return nil, E.New("client_certificate is not supported on naive-xhttp outbound")
	}
	if len(options.TLS.ClientKey) > 0 || options.TLS.ClientKeyPath != "" {
		return nil, E.New("client_key is not supported on naive-xhttp outbound")
	}
	if options.TLS.Fragment || options.TLS.RecordFragment {
		return nil, E.New("fragment is not supported on naive-xhttp outbound")
	}
	if options.TLS.KernelTx || options.TLS.KernelRx {
		return nil, E.New("kernel TLS is not supported on naive-xhttp outbound")
	}
	if options.TLS.UTLS != nil && options.TLS.UTLS.Enabled {
		return nil, E.New("uTLS is not supported on naive-xhttp outbound")
	}
	if options.TLS.Reality != nil && options.TLS.Reality.Enabled {
		return nil, E.New("reality is not supported on naive-xhttp outbound")
	}
	if options.HTTP1 && options.QUIC {
		return nil, E.New("http1 and quic are mutually exclusive on naive-xhttp outbound")
	}

	serverAddress := options.ServerOptions.Build()
	serverName := options.TLS.ServerName
	if serverName == "" {
		serverName = serverAddress.AddrString()
	}
	if options.Host != "" {
		if options.TLS.ServerName != "" && options.Host != options.TLS.ServerName {
			return nil, E.New("host and tls.server_name must match on naive-xhttp outbound")
		}
		serverName = options.Host
	}

	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   true,
		ResolverOnDetour: true,
		NewDialer:        true,
	})
	if err != nil {
		return nil, err
	}

	var trustedRootCertificates string
	if len(options.TLS.Certificate) > 0 {
		trustedRootCertificates = strings.Join(options.TLS.Certificate, "\n")
	} else if options.TLS.CertificatePath != "" {
		content, err := os.ReadFile(options.TLS.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		trustedRootCertificates = string(content)
	}

	extraHeaders := make(map[string]string)
	for key, values := range options.ExtraHeaders.Build() {
		if len(values) > 0 {
			extraHeaders[key] = values[0]
		}
	}

	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	var dnsResolver cronet.DNSResolverFunc
	if dnsRouter != nil {
		dnsResolver = func(dnsContext context.Context, request *mDNS.Msg) *mDNS.Msg {
			response, err := dnsRouter.Exchange(dnsContext, request, outboundDialer.(dialer.ResolveDialer).QueryOptions())
			if err != nil {
				logger.Error("DNS exchange failed: ", err)
				return dns.FixedResponseStatus(request, mDNS.RcodeServerFailure)
			}
			return response
		}
	}

	var echEnabled bool
	var echConfigList []byte
	var echQueryServerName string
	if options.TLS.ECH != nil && options.TLS.ECH.Enabled {
		echEnabled = true
		echQueryServerName = options.TLS.ECH.QueryServerName
		var echConfig []byte
		if len(options.TLS.ECH.Config) > 0 {
			echConfig = []byte(strings.Join(options.TLS.ECH.Config, "\n"))
		} else if options.TLS.ECH.ConfigPath != "" {
			content, err := os.ReadFile(options.TLS.ECH.ConfigPath)
			if err != nil {
				return nil, E.Cause(err, "read ECH config")
			}
			echConfig = content
		}
		if len(echConfig) > 0 {
			block, rest := pem.Decode(echConfig)
			if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
				return nil, E.New("invalid ECH configs pem")
			}
			echConfigList = block.Bytes
		}
	}

	var quicCongestionControl cronet.QUICCongestionControl
	switch options.QUICCongestionControl {
	case "":
		quicCongestionControl = cronet.QUICCongestionControlDefault
	case "bbr":
		quicCongestionControl = cronet.QUICCongestionControlBBR
	case "bbr2":
		quicCongestionControl = cronet.QUICCongestionControlBBRv2
	case "cubic":
		quicCongestionControl = cronet.QUICCongestionControlCubic
	case "reno":
		quicCongestionControl = cronet.QUICCongestionControlReno
	default:
		return nil, E.New("unknown quic congestion control: ", options.QUICCongestionControl)
	}

	var client *cronet.NaiveClient
	var httpClient *http.Client
	var httpTransport *http.Transport
	var http1Access chan struct{}
	if options.HTTP1 {
		http1MaxConnections := options.HTTP1MaxConnections
		if http1MaxConnections <= 0 {
			http1MaxConnections = 2
		}
		http1Access = make(chan struct{}, http1MaxConnections)
		tlsConfig, err := boxTLS.NewClientWithOptions(boxTLS.ClientOptions{
			Context:       ctx,
			Logger:        logger,
			ServerAddress: serverName,
			Options:       *options.TLS,
		})
		if err != nil {
			return nil, err
		}
		tlsConfig.SetNextProtos([]string{"http/1.1"})
		tlsDialer := boxTLS.NewDialer(outboundDialer, tlsConfig)
		httpTransport = &http.Transport{
			DisableCompression: true,
			ForceAttemptHTTP2:  false,
			TLSNextProto:       make(map[string]func(string, *stdTLS.Conn) http.RoundTripper),
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return tlsDialer.DialTLSContext(ctx, serverAddress)
			},
		}
		httpClient = &http.Client{
			Transport: httpTransport,
		}
	} else {
		client, err = cronet.NewNaiveClient(cronet.NaiveClientOptions{
			Context:                  ctx,
			Logger:                   logger,
			ServerAddress:            serverAddress,
			ServerName:               serverName,
			ExtraHeaders:             extraHeaders,
			ReceiveWindow:            options.ReceiveWindow.Value(),
			TrustedRootCertificates:  trustedRootCertificates,
			Dialer:                   outboundDialer,
			DNSResolver:              dnsResolver,
			ECHEnabled:               echEnabled,
			ECHConfigList:            echConfigList,
			ECHQueryServerName:       echQueryServerName,
			QUIC:                     options.QUIC,
			QUICCongestionControl:    quicCongestionControl,
			QUICSessionReceiveWindow: options.QUICSessionReceiveWindow.Value(),
		})
		if err != nil {
			return nil, err
		}
	}

	var authorization string
	if options.Username != "" {
		authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(options.Username+":"+options.Password))
	}

	basePath, rawQuery := normalizeBasePath(options.Path)
	baseURL := url.URL{
		Scheme:   "https",
		Host:     net.JoinHostPort(serverName, strconv.Itoa(int(serverAddress.Port))),
		Path:     basePath,
		RawQuery: rawQuery,
	}

	maxUploadSize := options.MaxEachPostBytes
	if maxUploadSize <= 0 {
		maxUploadSize = defaultMaxEachPostBytes
	}
	uploadCoalesceBytes := options.UploadCoalesceBytes
	if uploadCoalesceBytes < 0 {
		return nil, E.New("invalid upload coalesce bytes: ", uploadCoalesceBytes)
	}
	if uploadCoalesceBytes > maxUploadSize {
		uploadCoalesceBytes = maxUploadSize
	}
	uploadCoalesceDelay := time.Duration(options.UploadCoalesceDelayMs) * time.Millisecond
	if uploadCoalesceDelay < 0 {
		return nil, E.New("invalid upload coalesce delay: ", options.UploadCoalesceDelayMs)
	}
	maxConcurrentPosts := options.MaxConcurrentPosts
	if maxConcurrentPosts <= 0 {
		maxConcurrentPosts = 1
	}

	var uotClient *uot.Client
	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if uotOptions.Enabled {
		uotClient = &uot.Client{
			Dialer:  &naiveXHTTPDialer{outbound: nil},
			Version: uotOptions.Version,
		}
	}
	var multiplexDialer *mux.Client
	xhttpDialer := &naiveXHTTPDialer{}
	if !uotOptions.Enabled {
		multiplexDialer, err = mux.NewClientWithOptions(xhttpDialer, logger, common.PtrValueOrDefault(options.Multiplex))
		if err != nil {
			return nil, err
		}
	}
	var networks []string
	if uotClient != nil {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	} else {
		networks = []string{N.NetworkTCP}
	}
	outbound := &Outbound{
		Adapter:             outbound.NewAdapterWithDialerOptions(C.TypeNaiveXHTTP, tag, networks, options.DialerOptions),
		ctx:                 ctx,
		logger:              logger,
		client:              client,
		httpClient:          httpClient,
		httpTransport:       httpTransport,
		http1Access:         http1Access,
		uotClient:           uotClient,
		multiplexDialer:     multiplexDialer,
		baseURL:             baseURL,
		extraHeaders:        extraHeaders,
		authorization:       authorization,
		maxUploadSize:       maxUploadSize,
		postInterval:        time.Duration(options.MinPostsIntervalMs) * time.Millisecond,
		uploadCoalesceBytes: uploadCoalesceBytes,
		uploadCoalesceDelay: uploadCoalesceDelay,
		maxConcurrentPosts:  maxConcurrentPosts,
		quic:                options.QUIC,
		http1:               options.HTTP1,
		postAccess:          make(chan struct{}, maxConcurrentPosts),
	}
	if uotClient != nil {
		uotClient.Dialer = &naiveXHTTPDialer{outbound: outbound}
	}
	xhttpDialer.outbound = outbound
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.http1 {
		return nil
	}
	err := h.client.Start()
	if err != nil {
		return err
	}
	h.executor = cronet.NewExecutor(func(executor cronet.Executor, command cronet.Runnable) {
		go func() {
			command.Run()
			command.Destroy()
		}()
	})
	h.roundTripper = &cronet.RoundTripper{
		Engine:   h.client.Engine(),
		Executor: h.executor,
	}
	h.logger.Info("NaiveXHTTP started, version: ", h.client.Engine().Version())
	return nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	if h.multiplexDialer != nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound naive-xhttp multiplex connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound naive-xhttp multiplex packet connection to ", destination)
		}
		return h.multiplexDialer.DialContext(ctx, network, destination)
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound naive-xhttp connection to ", destination)
		return h.dialXHTTP(ctx, destination)
	case N.NetworkUDP:
		if h.uotClient == nil {
			return nil, E.New("UDP is not supported unless UDP over TCP is enabled")
		}
		h.logger.InfoContext(ctx, "outbound naive-xhttp UoT packet connection to ", destination)
		return h.uotClient.DialContext(ctx, network, destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	if h.multiplexDialer != nil {
		h.logger.InfoContext(ctx, "outbound naive-xhttp multiplex packet connection to ", destination)
		return h.multiplexDialer.ListenPacket(ctx, destination)
	}
	if h.uotClient == nil {
		return nil, E.New("UDP is not supported unless UDP over TCP is enabled")
	}
	return h.uotClient.ListenPacket(ctx, destination)
}

func (h *Outbound) MultiplexEnabled() bool {
	return h.multiplexDialer != nil
}

func (h *Outbound) InterfaceUpdated() {
	if h.client != nil {
		h.client.Engine().CloseAllConnections()
	}
	if h.httpTransport != nil {
		h.httpTransport.CloseIdleConnections()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
}

func (h *Outbound) Close() error {
	var err error
	if h.multiplexDialer != nil {
		err = h.multiplexDialer.Close()
	}
	if h.client != nil {
		err = E.Append(err, h.client.Close(), func(err error) error {
			return err
		})
	}
	if h.executor != (cronet.Executor{}) {
		h.executor.Destroy()
	}
	if h.httpTransport != nil {
		h.httpTransport.CloseIdleConnections()
	}
	return err
}

func (h *Outbound) Client() *cronet.NaiveClient {
	return h.client
}

func (h *Outbound) dialXHTTP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	sessionID, err := newSessionID()
	if err != nil {
		return nil, err
	}
	downURL := h.sessionURL(sessionID, "")
	headers := h.requestHeaders(downURL, destination)
	connCtx, stopWatching, cancelConn := detachAfterDialContext(ctx)
	if h.http1 {
		release, err := h.acquireHTTP1(ctx)
		if err != nil {
			stopWatching()
			cancelConn()
			return nil, err
		}
		request, err := http.NewRequestWithContext(connCtx, http.MethodGet, downURL, nil)
		if err != nil {
			stopWatching()
			cancelConn()
			release()
			return nil, err
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, err := h.httpClient.Do(request)
		stopWatching()
		if err != nil {
			cancelConn()
			release()
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			cancelConn()
			release()
			return nil, E.New("unexpected response status: ", response.StatusCode)
		}
		writer := newPacketUploadWriter(connCtx, h, sessionID)
		return &splitConn{
			reader: response.Body,
			writer: writer,
			onClose: func() {
				cancelConn()
				release()
			},
		}, nil
	}
	conn := h.client.Engine().StreamEngine().CreateConn(connCtx, h.logger, true, false)
	err = conn.Start(http.MethodGet, downURL, headers, 0, true)
	if err != nil {
		stopWatching()
		cancelConn()
		return nil, err
	}
	responseHeaders, err := conn.WaitForHeadersContext(connCtx)
	stopWatching()
	if err != nil {
		conn.Close()
		cancelConn()
		return nil, err
	}
	if responseHeaders[":status"] != "200" {
		conn.Close()
		cancelConn()
		return nil, E.New("unexpected response status: ", responseHeaders[":status"])
	}
	writer := newPacketUploadWriter(connCtx, h, sessionID)
	return &splitConn{
		reader:  conn,
		writer:  writer,
		onClose: cancelConn,
	}, nil
}

func detachAfterDialContext(parent context.Context) (context.Context, func(), context.CancelFunc) {
	// Mux uses a short dial context for opening the underlying tunnel; the
	// returned XHTTP stream must survive that context after response headers.
	connCtx, cancel := context.WithCancel(context.WithoutCancel(parent))
	done := make(chan struct{})
	var doneOnce sync.Once
	stopWatching := func() {
		doneOnce.Do(func() {
			close(done)
		})
	}
	go func() {
		select {
		case <-parent.Done():
			cancel()
		case <-done:
		}
	}()
	return connCtx, stopWatching, cancel
}

func (h *Outbound) sessionURL(sessionID string, seq string) string {
	requestURL := h.baseURL
	requestURL.Path = appendPath(h.baseURL.Path, sessionID)
	if seq != "" {
		requestURL.Path = appendPath(requestURL.Path+"/", seq)
	}
	return requestURL.String()
}

func (h *Outbound) requestHeaders(rawURL string, destination M.Socksaddr) map[string]string {
	headers := map[string]string{
		"Accept":        "text/event-stream",
		"Cache-Control": "no-store",
		headerPadding:   generatePaddingHeader(),
		"Referer":       requestPadding(rawURL),
	}
	if destination.IsValid() {
		target := destination.String()
		headers[headerConnectAuthority] = target
		if h.http1 {
			headers["X-Naive-Target"] = target
		}
	}
	if h.authorization != "" {
		headers["Proxy-Authorization"] = h.authorization
	}
	if h.quic {
		headers["-force-quic"] = "true"
	}
	for key, value := range h.extraHeaders {
		headers[key] = value
	}
	return headers
}

func (h *Outbound) applyHeaders(request *http.Request, rawURL string, destination M.Socksaddr) {
	for key, value := range h.requestHeaders(rawURL, destination) {
		request.Header.Set(key, value)
	}
	request.Header.Set("Content-Type", "application/octet-stream")
}

func (h *Outbound) postPacket(ctx context.Context, sessionID string, seq uint64, payload []byte) error {
	rawURL := h.sessionURL(sessionID, strconv.FormatUint(seq, 10))
	postCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(postCtx, http.MethodPost, rawURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.ContentLength = int64(len(payload))
	h.applyHeaders(request, rawURL, M.Socksaddr{})
	response, err := h.postRoundTrip(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusOK {
		return E.New("unexpected upload response status: ", response.Status)
	}
	return nil
}

func (h *Outbound) postRoundTrip(request *http.Request) (*http.Response, error) {
	release, err := h.acquirePost(request.Context())
	if err != nil {
		return nil, err
	}
	defer release()
	if h.http1 {
		return h.httpClient.Do(request)
	}
	return h.roundTripper.RoundTrip(request)
}

func (h *Outbound) acquirePost(ctx context.Context) (func(), error) {
	if h.postAccess == nil {
		return func() {}, nil
	}
	select {
	case h.postAccess <- struct{}{}:
		var releaseOnce sync.Once
		return func() {
			releaseOnce.Do(func() {
				<-h.postAccess
			})
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *Outbound) acquireHTTP1(ctx context.Context) (func(), error) {
	if h.http1Access == nil {
		return func() {}, nil
	}
	select {
	case h.http1Access <- struct{}{}:
		var releaseOnce sync.Once
		return func() {
			releaseOnce.Do(func() {
				<-h.http1Access
			})
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type packetUploadWriter struct {
	ctx       context.Context
	outbound  *Outbound
	sessionID string
	uploads   chan []byte
	closed    chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	errAccess sync.Mutex
	err       error
}

func newPacketUploadWriter(ctx context.Context, outbound *Outbound, sessionID string) *packetUploadWriter {
	writer := &packetUploadWriter{
		ctx:       ctx,
		outbound:  outbound,
		sessionID: sessionID,
		uploads:   make(chan []byte, defaultMaxBufferedPosts),
		closed:    make(chan struct{}),
		done:      make(chan struct{}),
	}
	go writer.loop()
	return writer
}

func (w *packetUploadWriter) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	var written int
	for len(payload) > 0 {
		chunkSize := len(payload)
		if chunkSize > w.outbound.maxUploadSize {
			chunkSize = w.outbound.maxUploadSize
		}
		chunk := append([]byte(nil), payload[:chunkSize]...)
		select {
		case <-w.closed:
			return written, w.errorOrClosed()
		default:
		}
		select {
		case w.uploads <- chunk:
			written += chunkSize
			payload = payload[chunkSize:]
		case <-w.closed:
			return written, w.errorOrClosed()
		case <-w.done:
			return written, w.errorOrClosed()
		case <-w.ctx.Done():
			return written, w.ctx.Err()
		}
	}
	return written, nil
}

func (w *packetUploadWriter) Close() error {
	w.closeOnce.Do(func() {
		close(w.closed)
	})
	return nil
}

func (w *packetUploadWriter) loop() {
	defer close(w.done)
	var seq uint64
	var lastPost time.Time
	var pending []byte
	maxConcurrentPosts := w.outbound.maxConcurrentPosts
	if maxConcurrentPosts <= 0 {
		maxConcurrentPosts = 1
	}
	results := make(chan error, maxConcurrentPosts)
	var inFlight int
	waitPost := func() bool {
		select {
		case err := <-results:
			inFlight--
			if err != nil {
				w.setError(err)
				return false
			}
			return true
		case <-w.ctx.Done():
			w.setError(w.ctx.Err())
			return false
		}
	}
	sendPost := func(payload []byte) bool {
		for inFlight >= maxConcurrentPosts {
			if !waitPost() {
				return false
			}
		}
		if w.outbound.postInterval > 0 && !lastPost.IsZero() {
			delay := w.outbound.postInterval - time.Since(lastPost)
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-w.closed:
					timer.Stop()
					return false
				case <-w.ctx.Done():
					timer.Stop()
					w.setError(w.ctx.Err())
					return false
				}
			}
		}
		postSeq := seq
		seq++
		lastPost = time.Now()
		inFlight++
		go func() {
			results <- w.outbound.postPacket(w.ctx, w.sessionID, postSeq, payload)
		}()
		return true
	}
	for {
		payload, ok, err := w.nextPayload(&pending)
		if err != nil {
			w.setError(err)
			return
		}
		if !ok {
			break
		}
		if !sendPost(payload) {
			return
		}
	}
	for inFlight > 0 {
		if !waitPost() {
			return
		}
	}
}

func (w *packetUploadWriter) nextPayload(pending *[]byte) ([]byte, bool, error) {
	coalesceLimit := w.outbound.uploadCoalesceBytes
	if coalesceLimit <= 0 {
		return w.nextRawPayload(pending)
	}
	if coalesceLimit > w.outbound.maxUploadSize {
		coalesceLimit = w.outbound.maxUploadSize
	}
	if coalesceLimit <= 0 {
		return w.nextRawPayload(pending)
	}
	payload := make([]byte, 0, coalesceLimit)
	appendPayload := func(chunk []byte) {
		available := coalesceLimit - len(payload)
		if len(chunk) <= available {
			payload = append(payload, chunk...)
			*pending = nil
			return
		}
		payload = append(payload, chunk[:available]...)
		*pending = append((*pending)[:0], chunk[available:]...)
	}
	firstChunk, ok, err := w.nextRawPayload(pending)
	if err != nil || !ok {
		return nil, ok, err
	}
	appendPayload(firstChunk)
	if len(payload) >= coalesceLimit {
		return payload, true, nil
	}
	var timer *time.Timer
	var timerC <-chan time.Time
	if w.outbound.uploadCoalesceDelay > 0 {
		timer = time.NewTimer(w.outbound.uploadCoalesceDelay)
		timerC = timer.C
		defer timer.Stop()
	}
	for len(payload) < coalesceLimit {
		if len(*pending) > 0 {
			appendPayload(*pending)
			continue
		}
		if timerC == nil {
			select {
			case chunk := <-w.uploads:
				appendPayload(chunk)
			case <-w.closed:
				w.drainQueuedPayloads(&payload, pending, coalesceLimit)
				return payload, true, nil
			case <-w.ctx.Done():
				return nil, false, w.ctx.Err()
			default:
				return payload, true, nil
			}
			continue
		}
		select {
		case chunk := <-w.uploads:
			appendPayload(chunk)
		case <-timerC:
			return payload, true, nil
		case <-w.closed:
			w.drainQueuedPayloads(&payload, pending, coalesceLimit)
			return payload, true, nil
		case <-w.ctx.Done():
			return nil, false, w.ctx.Err()
		}
	}
	return payload, true, nil
}

func (w *packetUploadWriter) nextRawPayload(pending *[]byte) ([]byte, bool, error) {
	if len(*pending) > 0 {
		payload := *pending
		*pending = nil
		return payload, true, nil
	}
	select {
	case payload := <-w.uploads:
		return payload, true, nil
	case <-w.closed:
		select {
		case payload := <-w.uploads:
			return payload, true, nil
		default:
			return nil, false, nil
		}
	case <-w.ctx.Done():
		return nil, false, w.ctx.Err()
	}
}

func (w *packetUploadWriter) drainQueuedPayloads(payload *[]byte, pending *[]byte, limit int) {
	appendPayload := func(chunk []byte) bool {
		available := limit - len(*payload)
		if available <= 0 {
			*pending = append((*pending)[:0], chunk...)
			return false
		}
		if len(chunk) <= available {
			*payload = append(*payload, chunk...)
			return true
		}
		*payload = append(*payload, chunk[:available]...)
		*pending = append((*pending)[:0], chunk[available:]...)
		return false
	}
	for len(*payload) < limit {
		select {
		case chunk := <-w.uploads:
			if !appendPayload(chunk) {
				return
			}
		default:
			return
		}
	}
}

func (w *packetUploadWriter) setError(err error) {
	w.errAccess.Lock()
	w.err = err
	w.errAccess.Unlock()
	w.Close()
}

func (w *packetUploadWriter) errorOrClosed() error {
	w.errAccess.Lock()
	defer w.errAccess.Unlock()
	if w.err != nil {
		return w.err
	}
	return net.ErrClosed
}

type naiveXHTTPDialer struct {
	outbound *Outbound
}

func (d *naiveXHTTPDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if d.outbound == nil {
		return nil, net.ErrClosed
	}
	return d.outbound.dialXHTTP(ctx, destination)
}

func (d *naiveXHTTPDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
