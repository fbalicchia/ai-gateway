// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package extensionserver

import (
	"fmt"
	"strings"

	egextension "github.com/envoyproxy/gateway/proto/extension"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	htomv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	httpconnectionmanagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	aigv1a1 "github.com/envoyproxy/ai-gateway/api/v1alpha1"
	"github.com/envoyproxy/ai-gateway/internal/internalapi"
)

const (
	a2aBackendListenerName = "aigateway-a2a-backend-listener"
)

// maybeGenerateResourcesForA2AGateway generates the resources needed to support A2A Gateway functionality.
func (s *Server) maybeGenerateResourcesForA2AGateway(req *egextension.PostTranslateModifyRequest) error {
	if len(req.Listeners) == 0 || len(req.Routes) == 0 {
		return nil
	}

	// Create routes for the backend listener first to determine if A2A processing is needed.
	a2aBackendRoutes := s.createA2ARoutesForBackendListener(req.Routes)

	// Only create the backend listener if there are routes for it.
	if a2aBackendRoutes != nil {
		a2aHTTPFilters, accessLogConfig, err := s.extractA2ABackendFiltersFromProxyListener(req.Listeners)
		if err != nil {
			return fmt.Errorf("failed to extract A2A backend filters: %w", err)
		}
		l, err := s.createA2ABackendListener(a2aHTTPFilters, accessLogConfig)
		if err != nil {
			return fmt.Errorf("failed to create A2A backend listener: %w", err)
		}
		req.Listeners = append(req.Listeners, l)
		req.Routes = append(req.Routes, a2aBackendRoutes)
	}

	// Modify clusters to route to the A2A proxy on 127.0.0.1:9857.
	s.modifyA2AGatewayGeneratedCluster(req.Clusters)
	return nil
}

// createA2ABackendListener creates the backend listener for A2A Gateway.
func (s *Server) createA2ABackendListener(a2aHTTPFilters []*httpconnectionmanagerv3.HttpFilter, accessLogConfig []*accesslogv3.AccessLog) (*listenerv3.Listener, error) {
	httpConManager := &httpconnectionmanagerv3.HttpConnectionManager{
		StatPrefix: fmt.Sprintf("%s-http", a2aBackendListenerName),
		AccessLog:  accessLogConfig,
		RouteSpecifier: &httpconnectionmanagerv3.HttpConnectionManager_Rds{
			Rds: &httpconnectionmanagerv3.Rds{
				RouteConfigName: fmt.Sprintf("%s-route-config", a2aBackendListenerName),
				ConfigSource: &corev3.ConfigSource{
					ConfigSourceSpecifier: &corev3.ConfigSource_Ads{
						Ads: &corev3.AggregatedConfigSource{},
					},
					ResourceApiVersion: corev3.ApiVersion_V3,
				},
			},
		},
	}

	// Add A2A HTTP filters (like credential injection filters) to the backend listener.
	for _, filter := range a2aHTTPFilters {
		s.log.Info("Adding A2A HTTP filter to backend listener", "filterName", filter.Name)
		httpConManager.HttpFilters = append(httpConManager.HttpFilters, filter)
	}

	// Add header-to-metadata filter for A2A metadata headers.
	headersToMetadata := &htomv3.Config{}
	for h, m := range internalapi.A2AInternalHeadersToMetadata {
		headersToMetadata.RequestRules = append(headersToMetadata.RequestRules,
			&htomv3.Config_Rule{
				Header: h,
				OnHeaderPresent: &htomv3.Config_KeyValuePair{
					MetadataNamespace: aigv1a1.AIGatewayFilterMetadataNamespace,
					Key:               m,
					Type:              htomv3.Config_STRING,
				},
				Remove: strings.HasPrefix(h, internalapi.A2AMetadataHeaderPrefix),
			},
		)
	}
	a, err := toAny(headersToMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal A2A header-to-metadata filter config: %w", err)
	}
	httpConManager.HttpFilters = append(httpConManager.HttpFilters, &httpconnectionmanagerv3.HttpFilter{
		Name:       "envoy.filters.http.header_to_metadata",
		ConfigType: &httpconnectionmanagerv3.HttpFilter_TypedConfig{TypedConfig: a},
	})

	// Add Router filter as the terminal HTTP filter.
	a, err = toAny(&routerv3.Router{})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal router filter config: %w", err)
	}
	httpConManager.HttpFilters = append(httpConManager.HttpFilters, &httpconnectionmanagerv3.HttpFilter{
		Name:       wellknown.Router,
		ConfigType: &httpconnectionmanagerv3.HttpFilter_TypedConfig{TypedConfig: a},
	})

	a, err = toAny(httpConManager)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HTTP Connection Manager for A2A backend listener: %w", err)
	}
	return &listenerv3.Listener{
		Name: a2aBackendListenerName,
		Address: &corev3.Address{
			Address: &corev3.Address_SocketAddress{
				SocketAddress: &corev3.SocketAddress{
					Protocol: corev3.SocketAddress_TCP,
					Address:  "127.0.0.1",
					PortSpecifier: &corev3.SocketAddress_PortValue{
						PortValue: internalapi.A2ABackendListenerPort,
					},
				},
			},
		},
		FilterChains: []*listenerv3.FilterChain{
			{
				Filters: []*listenerv3.Filter{
					{
						Name:       wellknown.HTTPConnectionManager,
						ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: a},
					},
				},
			},
		},
	}, nil
}

// createA2ARoutesForBackendListener creates routes for the A2A backend listener.
// Returns nil if no A2A routes are found.
func (s *Server) createA2ARoutesForBackendListener(routes []*routev3.RouteConfiguration) *routev3.RouteConfiguration {
	var backendListenerRoutes []*routev3.Route
	for _, routeConfig := range routes {
		for _, vh := range routeConfig.VirtualHosts {
			var originalRoutes []*routev3.Route
			for _, route := range vh.Routes {
				if strings.Contains(route.Name, internalapi.A2APerBackendRefHTTPRoutePrefix) {
					s.log.Info("found A2A route, processing for backend listener", "route", route.Name)
					marshaled, err := proto.Marshal(route)
					if err != nil {
						s.log.Error(err, "failed to marshal A2A route for backend listener", "route", route)
						continue
					}
					copiedRoute := &routev3.Route{}
					if err := proto.Unmarshal(marshaled, copiedRoute); err != nil {
						s.log.Error(err, "failed to unmarshal A2A route for backend listener", "route", route)
						continue
					}
					if routeAction := route.GetRoute(); routeAction != nil {
						if _, ok := routeAction.ClusterSpecifier.(*routev3.RouteAction_Cluster); ok {
							backendListenerRoutes = append(backendListenerRoutes, copiedRoute)
							continue
						}
					}
				}
				originalRoutes = append(originalRoutes, route)
			}
			vh.Routes = originalRoutes
		}
	}
	if len(backendListenerRoutes) == 0 {
		return nil
	}

	s.log.Info("created routes for A2A backend listener", "numRoutes", len(backendListenerRoutes))
	return &routev3.RouteConfiguration{
		Name: fmt.Sprintf("%s-route-config", a2aBackendListenerName),
		VirtualHosts: []*routev3.VirtualHost{
			{
				Name:    fmt.Sprintf("%s-wildcard", a2aBackendListenerName),
				Domains: []string{"*"},
				Routes:  backendListenerRoutes,
			},
		},
	}
}

// extractA2ABackendFiltersFromProxyListener extracts A2A-related HTTP filters from existing listeners.
func (s *Server) extractA2ABackendFiltersFromProxyListener(listeners []*listenerv3.Listener) ([]*httpconnectionmanagerv3.HttpFilter, []*accesslogv3.AccessLog, error) {
	var (
		a2aHTTPFilters  []*httpconnectionmanagerv3.HttpFilter
		accessLogConfig []*accesslogv3.AccessLog
	)

	for _, listener := range listeners {
		if listener.Name == a2aBackendListenerName {
			continue
		}

		filterChains := listener.GetFilterChains()
		defaultFC := listener.DefaultFilterChain
		if defaultFC != nil {
			filterChains = append(filterChains, defaultFC)
		}

		for _, chain := range filterChains {
			httpConManager, hcmIndex, err := findHCM(chain)
			if err != nil {
				continue
			}

			accessLogConfig = httpConManager.AccessLog

			var remainingFilters []*httpconnectionmanagerv3.HttpFilter
			for _, filter := range httpConManager.HttpFilters {
				if s.isA2ABackendHTTPFilter(filter) {
					s.log.Info("Found A2A HTTP filter, extracting from original listener", "filterName", filter.Name, "listener", listener.Name)
					a2aHTTPFilters = append(a2aHTTPFilters, filter)
				} else {
					remainingFilters = append(remainingFilters, filter)
				}
			}

			if len(remainingFilters) != len(httpConManager.HttpFilters) {
				httpConManager.HttpFilters = remainingFilters
				tc := &listenerv3.Filter_TypedConfig{}
				tc.TypedConfig, err = toAny(httpConManager)
				chain.Filters[hcmIndex].ConfigType = tc
				if err != nil {
					return nil, nil, fmt.Errorf("failed to marshal updated HCM for listener %s: %w", listener.Name, err)
				}
			}
		}
	}

	return a2aHTTPFilters, accessLogConfig, nil
}

// isA2ABackendHTTPFilter checks if an HTTP filter is used for A2A backend processing.
func (s *Server) isA2ABackendHTTPFilter(filter *httpconnectionmanagerv3.HttpFilter) bool {
	return strings.Contains(filter.Name, internalapi.A2APerBackendHTTPRouteFilterPrefix)
}

// modifyA2AGatewayGeneratedCluster updates A2A proxy clusters to point to localhost:9857.
func (s *Server) modifyA2AGatewayGeneratedCluster(clusters []*clusterv3.Cluster) {
	for _, c := range clusters {
		if strings.Contains(c.Name, internalapi.A2AMainHTTPRoutePrefix) && strings.HasSuffix(c.Name, "/rule/0") {
			name := c.Name
			*c = clusterv3.Cluster{
				Name:                 name,
				ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC},
				ConnectTimeout:       &durationpb.Duration{Seconds: 10},
				LoadAssignment: &endpointv3.ClusterLoadAssignment{
					ClusterName: name,
					Endpoints: []*endpointv3.LocalityLbEndpoints{
						{
							LbEndpoints: []*endpointv3.LbEndpoint{
								{
									HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
										Endpoint: &endpointv3.Endpoint{
											Address: &corev3.Address{
												Address: &corev3.Address_SocketAddress{
													SocketAddress: &corev3.SocketAddress{
														Address: "127.0.0.1",
														PortSpecifier: &corev3.SocketAddress_PortValue{
															PortValue: internalapi.A2AProxyPort,
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}
		}
	}
}
