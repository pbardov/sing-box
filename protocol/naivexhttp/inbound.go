package naivexhttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	sHttp "github.com/sagernet/sing/protocol/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.NaiveXHTTPInboundOptions](registry, C.TypeNaiveXHTTP, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx              context.Context
	router           adapter.ConnectionRouterEx
	logger           logger.ContextLogger
	options          option.NaiveXHTTPInboundOptions
	listener         *listener.Listener
	network          []string
	networkIsDefault bool
	authenticator    *auth.Authenticator
	tlsConfig        tls.ServerConfig
	httpServer       *http.Server
	path             string
	host             string
	maxEachPostBytes int
	maxBufferedPosts int
	sessions         sync.Map
	sessionAccess    sync.Mutex
}

type inboundSession struct {
	queue     *uploadQueue
	connected chan struct{}
	once      sync.Once
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveXHTTPInboundOptions) (adapter.Inbound, error) {
	basePath, _ := normalizeBasePath(options.Path)
	var networks []string
	if options.Network == "" {
		networks = []string{N.NetworkTCP}
	} else {
		networks = options.Network.Build()
	}
	for _, networkName := range networks {
		if networkName != N.NetworkTCP {
			return nil, E.New("naive-xhttp inbound supports TCP only")
		}
	}
	if len(options.Users) == 0 {
		return nil, E.New("missing users")
	}
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeNaiveXHTTP, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		options: options,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		networkIsDefault: options.Network == "",
		network:          networks,
		authenticator:    auth.NewAuthenticator(options.Users),
		path:             basePath,
		host:             options.Host,
		maxEachPostBytes: options.MaxEachPostBytes,
		maxBufferedPosts: options.MaxBufferedPosts,
	}
	if inbound.maxEachPostBytes <= 0 {
		inbound.maxEachPostBytes = defaultMaxEachPostBytes
	}
	if inbound.maxBufferedPosts <= 0 {
		inbound.maxBufferedPosts = defaultMaxBufferedPosts
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}
	return inbound, nil
}

func (n *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if n.tlsConfig != nil {
		err := n.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	tcpListener, err := n.listener.ListenTCP()
	if err != nil {
		return err
	}
	n.httpServer = &http.Server{
		Handler: h2c.NewHandler(n, &http2.Server{}),
		BaseContext: func(listener net.Listener) context.Context {
			return n.ctx
		},
	}
	listener := net.Listener(tcpListener)
	if n.tlsConfig != nil {
		if len(n.tlsConfig.NextProtos()) == 0 {
			n.tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
		} else if !common.Contains(n.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			n.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, n.tlsConfig.NextProtos()...))
		}
		listener = aTLS.NewListener(tcpListener, n.tlsConfig)
	}
	go func() {
		sErr := n.httpServer.Serve(listener)
		if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			n.logger.Error("http server serve error: ", sErr)
		}
	}()
	return nil
}

func (n *Inbound) Close() error {
	return common.Close(
		n.listener,
		common.PtrOrNil(n.httpServer),
		n.tlsConfig,
	)
}

func (n *Inbound) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if !n.validateHost(request.Host) {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	sessionID, seq, ok := n.extractMeta(request)
	if !ok {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if request.Method == http.MethodOptions {
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		writer.Header().Set("Access-Control-Allow-Headers", "*")
		writer.WriteHeader(http.StatusOK)
		return
	}
	switch request.Method {
	case http.MethodGet:
		if seq != "" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		n.handleDownlink(writer, request, sessionID)
	case http.MethodPost:
		if seq == "" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		n.handleUpload(writer, request, sessionID, seq)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (n *Inbound) validateHost(requestHost string) bool {
	if n.host == "" {
		return true
	}
	if strings.EqualFold(requestHost, n.host) {
		return true
	}
	host, _, err := net.SplitHostPort(requestHost)
	if err != nil {
		return false
	}
	return strings.EqualFold(host, n.host)
}

func (n *Inbound) extractMeta(request *http.Request) (sessionID string, seq string, ok bool) {
	if !strings.HasPrefix(request.URL.Path, n.path) {
		return "", "", false
	}
	suffix := strings.TrimPrefix(request.URL.Path, n.path)
	parts := strings.Split(strings.Trim(suffix, "/"), "/")
	if len(parts) < 1 || len(parts) > 2 || !validSessionID(parts[0]) {
		return "", "", false
	}
	if len(parts) == 2 {
		if parts[1] == "" {
			return "", "", false
		}
		if _, err := strconv.ParseUint(parts[1], 10, 64); err != nil {
			return "", "", false
		}
		seq = parts[1]
	}
	return parts[0], seq, true
}

func (n *Inbound) authenticate(writer http.ResponseWriter, request *http.Request) (string, bool) {
	userName, password, authOk := sHttp.ParseBasicAuth(request.Header.Get("Proxy-Authorization"))
	if authOk {
		authOk = n.authenticator.Verify(userName, password)
	}
	if !authOk {
		writer.WriteHeader(http.StatusProxyAuthRequired)
		n.badRequest(request.Context(), request, E.New("authorization failed"))
		return "", false
	}
	return userName, true
}

func (n *Inbound) handleUpload(writer http.ResponseWriter, request *http.Request, sessionID string, seqString string) {
	_, authOk := n.authenticate(writer, request)
	if !authOk {
		return
	}
	if request.ContentLength > int64(n.maxEachPostBytes) {
		writer.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, int64(n.maxEachPostBytes)+1))
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		n.badRequest(request.Context(), request, E.Cause(err, "read upload"))
		return
	}
	if len(payload) > n.maxEachPostBytes {
		writer.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	seq, err := strconv.ParseUint(seqString, 10, 64)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	session := n.upsertSession(sessionID)
	err = session.queue.push(uploadPacket{
		payload: payload,
		seq:     seq,
	})
	if err != nil {
		writer.WriteHeader(http.StatusConflict)
		n.badRequest(request.Context(), request, E.Cause(err, "push upload"))
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.WriteHeader(http.StatusOK)
}

func (n *Inbound) handleDownlink(writer http.ResponseWriter, request *http.Request, sessionID string) {
	ctx := log.ContextWithNewID(request.Context())
	userName, authOk := n.authenticate(writer, request)
	if !authOk {
		return
	}
	padding := request.Header.Get(headerPadding)
	if padding == "" {
		padding = extractXPadding(request)
	}
	if padding == "" || !cleanHeader(padding) {
		writer.WriteHeader(http.StatusBadRequest)
		n.badRequest(ctx, request, E.New("missing xhttp padding"))
		return
	}
	target := request.Header.Get(headerConnectAuthority)
	if target == "" {
		target = request.Header.Get("X-Naive-Target")
	}
	if target == "" || !cleanHeader(target) {
		writer.WriteHeader(http.StatusBadRequest)
		n.badRequest(ctx, request, E.New("missing target"))
		return
	}
	destination := M.ParseSocksaddr(target).Unwrap()
	if !destination.IsValid() || destination.Port == 0 {
		writer.WriteHeader(http.StatusBadRequest)
		n.badRequest(ctx, request, E.New("invalid target"))
		return
	}

	session := n.upsertSession(sessionID)
	session.once.Do(func() {
		close(session.connected)
	})
	defer n.deleteSession(sessionID, session)

	writer.Header().Set("X-Accel-Buffering", "no")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	if !n.options.NoSSEHeader {
		writer.Header().Set("Content-Type", "text/event-stream")
	}
	writer.Header().Set(headerPadding, generatePaddingHeader())
	writer.WriteHeader(http.StatusOK)
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}

	source := sHttp.SourceAddress(request)
	responseConn := newResponseWriterConn(writer, func() {
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
		}
	})
	var localAddr M.Socksaddr
	if rawLocalAddr := request.Context().Value(http.LocalAddrContextKey); rawLocalAddr != nil {
		if netLocalAddr, ok := rawLocalAddr.(net.Addr); ok {
			localAddr = M.SocksaddrFromNet(netLocalAddr).Unwrap()
		}
	}
	conn := &splitConn{
		reader:     session.queue,
		writer:     responseConn,
		localAddr:  localAddr,
		remoteAddr: source,
	}
	n.newConnection(ctx, conn, userName, source, destination, sessionID)

	select {
	case <-request.Context().Done():
		conn.Close()
	case <-responseConn.Wait():
	}
}

func (n *Inbound) upsertSession(sessionID string) *inboundSession {
	if session, loaded := n.sessions.Load(sessionID); loaded {
		return session.(*inboundSession)
	}
	n.sessionAccess.Lock()
	defer n.sessionAccess.Unlock()
	if session, loaded := n.sessions.Load(sessionID); loaded {
		return session.(*inboundSession)
	}
	session := &inboundSession{
		queue:     newUploadQueue(n.maxBufferedPosts),
		connected: make(chan struct{}),
	}
	n.sessions.Store(sessionID, session)
	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			n.deleteSession(sessionID, session)
		case <-session.connected:
		}
	}()
	return session
}

func (n *Inbound) deleteSession(sessionID string, session *inboundSession) {
	n.sessions.CompareAndDelete(sessionID, session)
	session.queue.Close()
}

func (n *Inbound) newConnection(ctx context.Context, conn net.Conn, userName string, source M.Socksaddr, destination M.Socksaddr, sessionID string) {
	if userName != "" {
		n.logger.InfoContext(ctx, "[", userName, "] inbound naive-xhttp connection from ", source)
		n.logger.InfoContext(ctx, "[", userName, "] inbound naive-xhttp connection to ", destination)
	} else {
		n.logger.InfoContext(ctx, "inbound naive-xhttp connection from ", source)
		n.logger.InfoContext(ctx, "inbound naive-xhttp connection to ", destination)
	}
	var metadata adapter.InboundContext
	metadata.Inbound = n.Tag()
	metadata.InboundType = n.Type()
	//nolint:staticcheck
	metadata.InboundDetour = n.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata.User = userName

	done := make(chan struct{})
	n.router.RouteConnectionEx(ctx, conn, metadata, N.OnceClose(func(err error) {
		close(done)
	}))
	go func() {
		<-done
		conn.Close()
		n.logger.DebugContext(ctx, "naive-xhttp session closed: ", sessionID)
	}()
}

func (n *Inbound) badRequest(ctx context.Context, request *http.Request, err error) {
	n.logger.ErrorContext(ctx, E.Cause(err, "process naive-xhttp request from ", request.RemoteAddr))
}
