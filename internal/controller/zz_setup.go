// SPDX-FileCopyrightText: 2024 The Crossplane Authors <https://crossplane.io>
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/upjet/pkg/controller"

	record "github.com/vibe/provider-infoblox/internal/controller/a/record"
	recordaaaa "github.com/vibe/provider-infoblox/internal/controller/aaaa/record"
	recordcname "github.com/vibe/provider-infoblox/internal/controller/cname/record"
	view "github.com/vibe/provider-infoblox/internal/controller/dns/view"
	allocation "github.com/vibe/provider-infoblox/internal/controller/ip/allocation"
	association "github.com/vibe/provider-infoblox/internal/controller/ip/association"
	network "github.com/vibe/provider-infoblox/internal/controller/ipv4/network"
	networkcontainer "github.com/vibe/provider-infoblox/internal/controller/ipv4/networkcontainer"
	networkipv6 "github.com/vibe/provider-infoblox/internal/controller/ipv6/network"
	networkcontaineripv6 "github.com/vibe/provider-infoblox/internal/controller/ipv6/networkcontainer"
	recordmx "github.com/vibe/provider-infoblox/internal/controller/mx/record"
	viewnetwork "github.com/vibe/provider-infoblox/internal/controller/network/view"
	providerconfig "github.com/vibe/provider-infoblox/internal/controller/providerconfig"
	recordptr "github.com/vibe/provider-infoblox/internal/controller/ptr/record"
	recordsrv "github.com/vibe/provider-infoblox/internal/controller/srv/record"
	recordtxt "github.com/vibe/provider-infoblox/internal/controller/txt/record"
	auth "github.com/vibe/provider-infoblox/internal/controller/zone/auth"
)

// Setup creates all controllers with the supplied logger and adds them to
// the supplied manager.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	for _, setup := range []func(ctrl.Manager, controller.Options) error{
		record.Setup,
		recordaaaa.Setup,
		recordcname.Setup,
		view.Setup,
		allocation.Setup,
		association.Setup,
		network.Setup,
		networkcontainer.Setup,
		networkipv6.Setup,
		networkcontaineripv6.Setup,
		recordmx.Setup,
		viewnetwork.Setup,
		providerconfig.Setup,
		recordptr.Setup,
		recordsrv.Setup,
		recordtxt.Setup,
		auth.Setup,
	} {
		if err := setup(mgr, o); err != nil {
			return err
		}
	}
	return nil
}
