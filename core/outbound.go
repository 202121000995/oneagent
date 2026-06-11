package core

import "log"

func InitOutbounds(outbounds []OutboundConfig) {
	for _, out := range outbounds {
		log.Printf("init outbound: %s %s -> %s:%d", out.Name, out.Protocol, out.Address, out.Port)
	}
}
