package option

import (
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

type NaiveXHTTPInboundOptions struct {
	ListenOptions
	Users            []auth.User `json:"users,omitempty"`
	Network          NetworkList `json:"network,omitempty"`
	Path             string      `json:"path,omitempty"`
	Host             string      `json:"host,omitempty"`
	MaxEachPostBytes int         `json:"sc_max_each_post_bytes,omitempty"`
	MaxBufferedPosts int         `json:"sc_max_buffered_posts,omitempty"`
	NoSSEHeader      bool        `json:"no_sse_header,omitempty"`
	InboundTLSOptionsContainer
	Multiplex *InboundMultiplexOptions `json:"multiplex,omitempty"`
}

type NaiveXHTTPOutboundOptions struct {
	DialerOptions
	ServerOptions
	Username                 string                    `json:"username,omitempty"`
	Password                 string                    `json:"password,omitempty"`
	Path                     string                    `json:"path,omitempty"`
	Host                     string                    `json:"host,omitempty"`
	ExtraHeaders             badoption.HTTPHeader      `json:"extra_headers,omitempty"`
	MaxEachPostBytes         int                       `json:"sc_max_each_post_bytes,omitempty"`
	MinPostsIntervalMs       int                       `json:"sc_min_posts_interval_ms,omitempty"`
	UploadCoalesceBytes      int                       `json:"sc_upload_coalesce_bytes,omitempty"`
	UploadCoalesceDelayMs    int                       `json:"sc_upload_coalesce_delay_ms,omitempty"`
	MaxConcurrentPosts       int                       `json:"sc_max_concurrent_posts,omitempty"`
	HTTP1                    bool                      `json:"http1,omitempty"`
	HTTP1MaxConnections      int                       `json:"http1_max_connections,omitempty"`
	ReceiveWindow            *byteformats.MemoryBytes  `json:"stream_receive_window,omitempty"`
	UDPOverTCP               *UDPOverTCPOptions        `json:"udp_over_tcp,omitempty"`
	Multiplex                *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	QUIC                     bool                      `json:"quic,omitempty"`
	QUICCongestionControl    string                    `json:"quic_congestion_control,omitempty"`
	QUICSessionReceiveWindow *byteformats.MemoryBytes  `json:"quic_session_receive_window,omitempty"`
	OutboundTLSOptionsContainer
}
