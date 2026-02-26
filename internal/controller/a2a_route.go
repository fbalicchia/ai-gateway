// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package controller

import (
	"context"
	"fmt"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlutil "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	aigv1a1 "github.com/envoyproxy/ai-gateway/api/v1alpha1"
	"github.com/envoyproxy/ai-gateway/internal/internalapi"
)

const (
	defaultA2APath         = "/a2a"
	a2aProxyBackendDummyIP = "192.0.2.43" // RFC 5737 TEST-NET-2, used as a dummy IP.
)

// A2ARouteController implements [reconcile.TypedReconciler].
//
// This handles the A2ARoute resource and creates the necessary resources for the A2A proxy.
//
// Exported for testing purposes.
type A2ARouteController struct {
	client client.Client
	kube   kubernetes.Interface
	logger logr.Logger
	// gatewayEventChan is a channel to send events to the gateway controller.
	gatewayEventChan chan event.GenericEvent
}

// NewA2ARouteController creates a new reconcile.TypedReconciler[reconcile.Request] for the A2ARoute resource.
func NewA2ARouteController(
	client client.Client, kube kubernetes.Interface, logger logr.Logger,
	gatewayEventChan chan event.GenericEvent,
) *A2ARouteController {
	return &A2ARouteController{
		client:           client,
		kube:             kube,
		logger:           logger,
		gatewayEventChan: gatewayEventChan,
	}
}

// Reconcile implements [reconcile.TypedReconciler].
func (c *A2ARouteController) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	c.logger.Info("Reconciling A2ARoute", "namespace", req.Namespace, "name", req.Name)

	var a2aRoute aigv1a1.A2ARoute
	if err := c.client.Get(ctx, req.NamespacedName, &a2aRoute); err != nil {
		if client.IgnoreNotFound(err) == nil {
			c.logger.Info("Deleting A2ARoute", "namespace", req.Namespace, "name", req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if err := c.syncA2ARoute(ctx, &a2aRoute); err != nil {
		c.logger.Error(err, "failed to sync A2ARoute")
		c.updateA2ARouteStatus(ctx, &a2aRoute, aigv1a1.ConditionTypeNotAccepted, err.Error())
		return ctrl.Result{}, err
	}
	c.updateA2ARouteStatus(ctx, &a2aRoute, aigv1a1.ConditionTypeAccepted, "A2A Gateway Route reconciled successfully")
	return reconcile.Result{}, nil
}

// syncA2ARoute is the main logic for reconciling the A2ARoute resource.
func (c *A2ARouteController) syncA2ARoute(ctx context.Context, a2aRoute *aigv1a1.A2ARoute) error {
	if handleFinalizer(ctx, c.client, c.logger, a2aRoute, c.syncGateways) {
		return nil
	}

	// Ensure the A2A proxy Backend exists before creating/updating the HTTPRoute.
	if err := c.ensureA2AProxyBackend(ctx, a2aRoute); err != nil {
		return fmt.Errorf("failed to ensure A2A proxy Backend: %w", err)
	}
	c.logger.Info("Syncing A2ARoute", "namespace", a2aRoute.Namespace, "name", a2aRoute.Name)

	// Create or update the main HTTPRoute that routes to the A2A proxy.
	mainHTTPRouteName := internalapi.A2AMainHTTPRoutePrefix + a2aRoute.Name
	mainHTTPRoute, existing, err := c.getOrNewA2AHTTPRoute(ctx, a2aRoute, mainHTTPRouteName)
	if err != nil {
		return fmt.Errorf("failed to get or create HTTPRoute: %w", err)
	}
	c.newMainA2AHTTPRoute(mainHTTPRoute, a2aRoute)

	if err = c.createOrUpdateA2AHTTPRoute(ctx, mainHTTPRoute, existing); err != nil {
		return fmt.Errorf("failed to create or update main HTTPRoute: %w", err)
	}

	// Create per-backend HTTPRoutes.
	for i := range a2aRoute.Spec.BackendRefs {
		ref := &a2aRoute.Spec.BackendRefs[i]
		name := a2aPerBackendRefHTTPRouteName(a2aRoute.Name, ref.Name)
		var httpRoute *gwapiv1.HTTPRoute
		httpRoute, existing, err = c.getOrNewA2AHTTPRoute(ctx, a2aRoute, name)
		if err != nil {
			return fmt.Errorf("failed to get or create per-backend HTTPRoute: %w", err)
		}
		if err = c.newPerBackendRefA2AHTTPRoute(ctx, httpRoute, a2aRoute, ref); err != nil {
			return fmt.Errorf("failed to construct per-backend HTTPRoute for %s: %w", ref.Name, err)
		}
		if err = c.createOrUpdateA2AHTTPRoute(ctx, httpRoute, existing); err != nil {
			return fmt.Errorf("failed to create or update per-backend HTTPRoute for %s: %w", ref.Name, err)
		}
	}

	return c.syncGateways(ctx, a2aRoute)
}

// newMainA2AHTTPRoute updates the main HTTPRoute spec for the A2ARoute.
func (c *A2ARouteController) newMainA2AHTTPRoute(dst *gwapiv1.HTTPRoute, a2aRoute *aigv1a1.A2ARoute) {
	servingPath := ptr.Deref(a2aRoute.Spec.Path, defaultA2APath)
	rules := []gwapiv1.HTTPRouteRule{
		{
			Matches: []gwapiv1.HTTPRouteMatch{
				{
					Path: &gwapiv1.HTTPPathMatch{
						Type:  ptr.To(gwapiv1.PathMatchExact),
						Value: ptr.To(servingPath),
					},
				},
			},
			BackendRefs: []gwapiv1.HTTPBackendRef{
				{
					BackendRef: gwapiv1.BackendRef{
						BackendObjectReference: gwapiv1.BackendObjectReference{
							Group:     ptr.To(gwapiv1.Group("gateway.envoyproxy.io")),
							Kind:      ptr.To(gwapiv1.Kind("Backend")),
							Name:      gwapiv1.ObjectName(a2aProxyBackendName(a2aRoute)),
							Namespace: ptr.To(gwapiv1.Namespace(a2aRoute.Namespace)),
							Port:      ptr.To(gwapiv1.PortNumber(internalapi.A2AProxyPort)),
						},
					},
				},
			},
			Timeouts: &gwapiv1.HTTPRouteTimeouts{
				Request:        ptr.To(gwapiv1.Duration("30m")),
				BackendRequest: ptr.To(gwapiv1.Duration("30m")),
			},
			Filters: []gwapiv1.HTTPRouteFilter{
				{
					Type: gwapiv1.HTTPRouteFilterRequestHeaderModifier,
					RequestHeaderModifier: &gwapiv1.HTTPHeaderFilter{
						Set: []gwapiv1.HTTPHeader{
							{
								Name:  internalapi.A2ARouteHeader,
								Value: a2aRouteHeaderValue(a2aRoute),
							},
						},
					},
				},
			},
		},
		// Agent card discovery endpoint.
		{
			Matches: []gwapiv1.HTTPRouteMatch{
				{
					Path: &gwapiv1.HTTPPathMatch{
						Type:  ptr.To(gwapiv1.PathMatchExact),
						Value: ptr.To("/.well-known/agent-card.json"),
					},
				},
			},
			BackendRefs: []gwapiv1.HTTPBackendRef{
				{
					BackendRef: gwapiv1.BackendRef{
						BackendObjectReference: gwapiv1.BackendObjectReference{
							Group:     ptr.To(gwapiv1.Group("gateway.envoyproxy.io")),
							Kind:      ptr.To(gwapiv1.Kind("Backend")),
							Name:      gwapiv1.ObjectName(a2aProxyBackendName(a2aRoute)),
							Namespace: ptr.To(gwapiv1.Namespace(a2aRoute.Namespace)),
							Port:      ptr.To(gwapiv1.PortNumber(internalapi.A2AProxyPort)),
						},
					},
				},
			},
			Filters: []gwapiv1.HTTPRouteFilter{
				{
					Type: gwapiv1.HTTPRouteFilterRequestHeaderModifier,
					RequestHeaderModifier: &gwapiv1.HTTPHeaderFilter{
						Set: []gwapiv1.HTTPHeader{
							{
								Name:  internalapi.A2ARouteHeader,
								Value: a2aRouteHeaderValue(a2aRoute),
							},
						},
					},
				},
			},
		},
		// Legacy agent card endpoint.
		{
			Matches: []gwapiv1.HTTPRouteMatch{
				{
					Path: &gwapiv1.HTTPPathMatch{
						Type:  ptr.To(gwapiv1.PathMatchExact),
						Value: ptr.To("/.well-known/agent.json"),
					},
				},
			},
			BackendRefs: []gwapiv1.HTTPBackendRef{
				{
					BackendRef: gwapiv1.BackendRef{
						BackendObjectReference: gwapiv1.BackendObjectReference{
							Group:     ptr.To(gwapiv1.Group("gateway.envoyproxy.io")),
							Kind:      ptr.To(gwapiv1.Kind("Backend")),
							Name:      gwapiv1.ObjectName(a2aProxyBackendName(a2aRoute)),
							Namespace: ptr.To(gwapiv1.Namespace(a2aRoute.Namespace)),
							Port:      ptr.To(gwapiv1.PortNumber(internalapi.A2AProxyPort)),
						},
					},
				},
			},
			Filters: []gwapiv1.HTTPRouteFilter{
				{
					Type: gwapiv1.HTTPRouteFilterRequestHeaderModifier,
					RequestHeaderModifier: &gwapiv1.HTTPHeaderFilter{
						Set: []gwapiv1.HTTPHeader{
							{
								Name:  internalapi.A2ARouteHeader,
								Value: a2aRouteHeaderValue(a2aRoute),
							},
						},
					},
				},
			},
		},
	}

	dst.Spec.Rules = rules
	dst.Spec.ParentRefs = a2aRoute.Spec.ParentRefs
}

// newPerBackendRefA2AHTTPRoute creates an HTTPRoute for each backend reference in the A2ARoute.
func (c *A2ARouteController) newPerBackendRefA2AHTTPRoute(ctx context.Context, dst *gwapiv1.HTTPRoute, a2aRoute *aigv1a1.A2ARoute, ref *aigv1a1.A2ARouteBackendRef) error {
	if ns := ref.Namespace; ns != nil && *ns != gwapiv1.Namespace(a2aRoute.Namespace) {
		return fmt.Errorf("cross-namespace backend reference is not supported: backend %s/%s in A2ARoute %s/%s",
			*ns, ref.Name, a2aRoute.Namespace, a2aRoute.Name)
	}

	rule, err := c.a2aBackendRefToHTTPRouteRule(ctx, a2aRoute, ref)
	if err != nil {
		return fmt.Errorf("failed to convert A2ARouteBackendRef to HTTPRouteRule: %w", err)
	}
	dst.Spec.Rules = []gwapiv1.HTTPRouteRule{rule}
	dst.Spec.ParentRefs = a2aRoute.Spec.ParentRefs
	return nil
}

// a2aBackendRefToHTTPRouteRule creates an HTTPRouteRule for the given A2ARouteBackendRef.
func (c *A2ARouteController) a2aBackendRefToHTTPRouteRule(ctx context.Context, a2aRoute *aigv1a1.A2ARoute, ref *aigv1a1.A2ARouteBackendRef) (gwapiv1.HTTPRouteRule, error) {
	egFilterName := a2aBackendRefFilterName(a2aRoute, ref.Name)
	err := c.ensureA2ABackendRefHTTPFilter(ctx, egFilterName, a2aRoute)
	if err != nil {
		return gwapiv1.HTTPRouteRule{}, fmt.Errorf("failed to ensure A2A backend HTTP filter: %w", err)
	}

	filters := []gwapiv1.HTTPRouteFilter{
		{
			Type: gwapiv1.HTTPRouteFilterExtensionRef,
			ExtensionRef: &gwapiv1.LocalObjectReference{
				Group: "gateway.envoyproxy.io",
				Kind:  "HTTPRouteFilter",
				Name:  gwapiv1.ObjectName(egFilterName),
			},
		},
	}

	fullPath := ptr.Deref(ref.Path, defaultA2APath)

	// Inject API key if configured.
	if ref.SecurityPolicy != nil && ref.SecurityPolicy.APIKey != nil {
		apiKey := ref.SecurityPolicy.APIKey
		apiKeyLiteral, readErr := c.readA2AAPIKey(ctx, a2aRoute.Namespace, apiKey)
		if readErr != nil {
			return gwapiv1.HTTPRouteRule{}, fmt.Errorf("failed to read API key for backend %s: %w", ref.Name, readErr)
		}
		switch {
		case apiKey.QueryParam != nil:
			fullPath = fmt.Sprintf("%s?%s=%s", fullPath, *apiKey.QueryParam, apiKeyLiteral)
		case apiKey.Header != nil:
			header := *apiKey.Header
			if header == "Authorization" {
				apiKeyLiteral = "Bearer " + apiKeyLiteral
			}
			filters = append(filters, gwapiv1.HTTPRouteFilter{
				Type: gwapiv1.HTTPRouteFilterRequestHeaderModifier,
				RequestHeaderModifier: &gwapiv1.HTTPHeaderFilter{
					Set: []gwapiv1.HTTPHeader{
						{Name: gwapiv1.HTTPHeaderName(header), Value: apiKeyLiteral},
					},
				},
			})
		default:
			filters = append(filters, gwapiv1.HTTPRouteFilter{
				Type: gwapiv1.HTTPRouteFilterRequestHeaderModifier,
				RequestHeaderModifier: &gwapiv1.HTTPHeaderFilter{
					Set: []gwapiv1.HTTPHeader{
						{Name: "Authorization", Value: "Bearer " + apiKeyLiteral},
					},
				},
			})
		}
	}

	filters = append(filters, gwapiv1.HTTPRouteFilter{
		Type: gwapiv1.HTTPRouteFilterURLRewrite,
		URLRewrite: &gwapiv1.HTTPURLRewriteFilter{
			Path: &gwapiv1.HTTPPathModifier{
				Type:            gwapiv1.FullPathHTTPPathModifier,
				ReplaceFullPath: ptr.To(fullPath),
			},
		},
	})

	return gwapiv1.HTTPRouteRule{
		Matches: []gwapiv1.HTTPRouteMatch{
			{
				Path: &gwapiv1.HTTPPathMatch{Type: ptr.To(gwapiv1.PathMatchPathPrefix), Value: ptr.To("/")},
				Headers: []gwapiv1.HTTPHeaderMatch{
					{Name: internalapi.A2ABackendHeader, Value: string(ref.Name)},
					{Name: internalapi.A2ARouteHeader, Value: a2aRouteHeaderValue(a2aRoute)},
				},
			},
		},
		Filters: filters,
		BackendRefs: []gwapiv1.HTTPBackendRef{{
			BackendRef: gwapiv1.BackendRef{
				BackendObjectReference: gwapiv1.BackendObjectReference{
					Group:     ref.Group,
					Kind:      ref.Kind,
					Name:      ref.Name,
					Namespace: ref.Namespace,
					Port:      ref.Port,
				},
			},
		}},
		Timeouts: &gwapiv1.HTTPRouteTimeouts{
			Request:        ptr.To(gwapiv1.Duration("30m")),
			BackendRequest: ptr.To(gwapiv1.Duration("30m")),
		},
	}, nil
}

// ensureA2ABackendRefHTTPFilter ensures an HTTPRouteFilter exists for the given backend reference.
func (c *A2ARouteController) ensureA2ABackendRefHTTPFilter(ctx context.Context, filterName string, a2aRoute *aigv1a1.A2ARoute) error {
	filter := &egv1a1.HTTPRouteFilter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      filterName,
			Namespace: a2aRoute.Namespace,
		},
		Spec: egv1a1.HTTPRouteFilterSpec{
			URLRewrite: &egv1a1.HTTPURLRewriteFilter{
				Hostname: &egv1a1.HTTPHostnameModifier{
					Type: egv1a1.BackendHTTPHostnameModifier,
				},
			},
		},
	}
	if err := ctrlutil.SetControllerReference(a2aRoute, filter, c.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference for HTTPRouteFilter: %w", err)
	}

	var existingFilter egv1a1.HTTPRouteFilter
	err := c.client.Get(ctx, client.ObjectKey{Name: filterName, Namespace: a2aRoute.Namespace}, &existingFilter)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get HTTPRouteFilter: %w", err)
	}
	if apierrors.IsNotFound(err) {
		c.logger.Info("Creating A2A HTTPRouteFilter", "namespace", filter.Namespace, "name", filter.Name)
		if err = c.client.Create(ctx, filter); err != nil {
			return fmt.Errorf("failed to create HTTPRouteFilter: %w", err)
		}
	} else {
		existingFilter.Spec = filter.Spec
		c.logger.Info("Updating A2A HTTPRouteFilter", "namespace", existingFilter.Namespace, "name", existingFilter.Name)
		if err = c.client.Update(ctx, &existingFilter); err != nil {
			return fmt.Errorf("failed to update HTTPRouteFilter: %w", err)
		}
	}
	return nil
}

// ensureA2AProxyBackend ensures that the A2A proxy Backend resource exists.
func (c *A2ARouteController) ensureA2AProxyBackend(ctx context.Context, a2aRoute *aigv1a1.A2ARoute) error {
	name := a2aProxyBackendName(a2aRoute)
	var backend egv1a1.Backend
	err := c.client.Get(ctx, client.ObjectKey{Name: name, Namespace: a2aRoute.Namespace}, &backend)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get A2A proxy Backend: %w", err)
	}
	if apierrors.IsNotFound(err) {
		backend = egv1a1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: a2aRoute.Namespace,
			},
			Spec: egv1a1.BackendSpec{
				Endpoints: []egv1a1.BackendEndpoint{
					{
						IP: &egv1a1.IPEndpoint{
							Address: a2aProxyBackendDummyIP,
							Port:    int32(internalapi.A2AProxyPort),
						},
					},
				},
			},
		}
		if err = ctrlutil.SetControllerReference(a2aRoute, &backend, c.client.Scheme()); err != nil {
			panic(fmt.Errorf("BUG: failed to set controller reference for A2A proxy Backend: %w", err))
		}
		c.logger.Info("Creating A2A proxy Backend", "namespace", a2aRoute.Namespace, "name", name)
		if err = c.client.Create(ctx, &backend); err != nil {
			return fmt.Errorf("failed to create A2A proxy Backend: %w", err)
		}
	}
	return nil
}

// syncGateways synchronizes the gateways referenced by the A2ARoute.
func (c *A2ARouteController) syncGateways(ctx context.Context, a2aRoute *aigv1a1.A2ARoute) error {
	for _, p := range a2aRoute.Spec.ParentRefs {
		gwNamespace := a2aRoute.Namespace
		if p.Namespace != nil {
			gwNamespace = string(*p.Namespace)
		}
		c.syncGatewayForA2A(ctx, gwNamespace, string(p.Name))
	}
	return nil
}

func (c *A2ARouteController) syncGatewayForA2A(ctx context.Context, namespace, name string) {
	var gw gwapiv1.Gateway
	if err := c.client.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, &gw); err != nil {
		if apierrors.IsNotFound(err) {
			c.logger.Info("Gateway not found for A2ARoute", "namespace", namespace, "name", name)
			return
		}
		c.logger.Error(err, "failed to get Gateway for A2ARoute", "namespace", namespace, "name", name)
		return
	}
	c.logger.Info("Syncing Gateway for A2ARoute", "namespace", gw.Namespace, "name", gw.Name)
	c.gatewayEventChan <- event.GenericEvent{Object: &gw}
}

// updateA2ARouteStatus updates the status of the A2ARoute.
func (c *A2ARouteController) updateA2ARouteStatus(ctx context.Context, route *aigv1a1.A2ARoute, conditionType string, message string) {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := c.client.Get(ctx, client.ObjectKey{Name: route.Name, Namespace: route.Namespace}, route); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}
		route.Status.Conditions = newConditions(conditionType, message)
		return c.client.Status().Update(ctx, route)
	})
	if err != nil {
		c.logger.Error(err, "failed to update A2ARoute status")
	}
}

// getOrNewA2AHTTPRoute fetches or initializes a new HTTPRoute for the A2ARoute.
func (c *A2ARouteController) getOrNewA2AHTTPRoute(ctx context.Context, a2aRoute *aigv1a1.A2ARoute, routeName string) (*gwapiv1.HTTPRoute, bool, error) {
	httpRoute := &gwapiv1.HTTPRoute{}
	err := c.client.Get(ctx, client.ObjectKey{Name: routeName, Namespace: a2aRoute.Namespace}, httpRoute)
	existing := err == nil
	if apierrors.IsNotFound(err) {
		httpRoute = &gwapiv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:        routeName,
				Namespace:   a2aRoute.Namespace,
				Labels:      make(map[string]string),
				Annotations: make(map[string]string),
			},
			Spec: gwapiv1.HTTPRouteSpec{},
		}
		for k, v := range a2aRoute.Labels {
			httpRoute.Labels[k] = v
		}
		for k, v := range a2aRoute.Annotations {
			httpRoute.Annotations[k] = v
		}
		if err = ctrlutil.SetControllerReference(a2aRoute, httpRoute, c.client.Scheme()); err != nil {
			return nil, false, fmt.Errorf("failed to set controller reference for HTTPRoute: %w", err)
		}
	} else if err != nil {
		return nil, false, fmt.Errorf("failed to get HTTPRoute: %w", err)
	}
	return httpRoute, existing, nil
}

// createOrUpdateA2AHTTPRoute creates or updates an HTTPRoute.
func (c *A2ARouteController) createOrUpdateA2AHTTPRoute(ctx context.Context, httpRoute *gwapiv1.HTTPRoute, update bool) error {
	if update {
		c.logger.Info("Updating A2A HTTPRoute", "namespace", httpRoute.Namespace, "name", httpRoute.Name)
		if err := c.client.Update(ctx, httpRoute); err != nil {
			return fmt.Errorf("failed to update A2A HTTPRoute: %w", err)
		}
	} else {
		c.logger.Info("Creating A2A HTTPRoute", "namespace", httpRoute.Namespace, "name", httpRoute.Name)
		if err := c.client.Create(ctx, httpRoute); err != nil {
			return fmt.Errorf("failed to create A2A HTTPRoute: %w", err)
		}
	}
	return nil
}

// readA2AAPIKey reads the API key from the secret or inline value.
func (c *A2ARouteController) readA2AAPIKey(ctx context.Context, namespace string, apiKey *aigv1a1.A2ABackendAPIKey) (string, error) {
	key := ptr.Deref(apiKey.Inline, "")
	if key == "" {
		secretRef := apiKey.SecretRef
		secret, err := c.kube.CoreV1().Secrets(namespace).Get(ctx, string(secretRef.Name), metav1.GetOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to get secret for API key: %w", err)
		}
		if k, ok := secret.Data["apiKey"]; ok {
			key = string(k)
		} else if key, ok = secret.StringData["apiKey"]; !ok {
			return "", fmt.Errorf("secret %s/%s does not contain 'apiKey' key", namespace, secretRef.Name)
		}
	}
	return key, nil
}

// Helper functions.

func a2aProxyBackendName(a2aRoute *aigv1a1.A2ARoute) string {
	return fmt.Sprintf("%s-%s-a2a-proxy", a2aRoute.Namespace, a2aRoute.Name)
}

func a2aBackendRefFilterName(a2aRoute *aigv1a1.A2ARoute, backendName gwapiv1.ObjectName) string {
	return fmt.Sprintf("%s%s-%s", internalapi.A2APerBackendHTTPRouteFilterPrefix, a2aRoute.Name, backendName)
}

func a2aPerBackendRefHTTPRouteName(a2aRouteName string, backendName gwapiv1.ObjectName) string {
	return fmt.Sprintf("%s%s-%s", internalapi.A2APerBackendRefHTTPRoutePrefix, a2aRouteName, backendName)
}

func a2aRouteHeaderValue(a2aRoute *aigv1a1.A2ARoute) string {
	return fmt.Sprintf("%s/%s", a2aRoute.Namespace, a2aRoute.Name)
}
