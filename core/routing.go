package core

import "log"

func InitRoutes(rules []RoutingRule) {
	for _, rule := range rules {
		log.Printf("init route: %s -> %s", rule.Inbound, rule.Outbound)
	}
}
