//go:build with_naive_outbound

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/protocol/naivexhttp"
)

func registerNaiveOutbound(registry *outbound.Registry) {
	naive.RegisterOutbound(registry)
	naivexhttp.RegisterOutbound(registry)
}
