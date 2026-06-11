package core

import "log"

func InitInbounds(inbounds []InboundConfig) {
	for _, inb := range inbounds {
		log.Printf("init inbound: %s %s:%d", inb.Name, inb.Protocol, inb.Port)
	}
}
