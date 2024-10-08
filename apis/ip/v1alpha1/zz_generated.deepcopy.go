//go:build !ignore_autogenerated

// SPDX-FileCopyrightText: 2024 The Crossplane Authors <https://crossplane.io>
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Allocation) DeepCopyInto(out *Allocation) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Allocation.
func (in *Allocation) DeepCopy() *Allocation {
	if in == nil {
		return nil
	}
	out := new(Allocation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Allocation) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AllocationInitParameters) DeepCopyInto(out *AllocationInitParameters) {
	*out = *in
	if in.AllocatedIPv4Addr != nil {
		in, out := &in.AllocatedIPv4Addr, &out.AllocatedIPv4Addr
		*out = new(string)
		**out = **in
	}
	if in.AllocatedIPv6Addr != nil {
		in, out := &in.AllocatedIPv6Addr, &out.AllocatedIPv6Addr
		*out = new(string)
		**out = **in
	}
	if in.Comment != nil {
		in, out := &in.Comment, &out.Comment
		*out = new(string)
		**out = **in
	}
	if in.DNSView != nil {
		in, out := &in.DNSView, &out.DNSView
		*out = new(string)
		**out = **in
	}
	if in.EnableDNS != nil {
		in, out := &in.EnableDNS, &out.EnableDNS
		*out = new(bool)
		**out = **in
	}
	if in.ExtAttrs != nil {
		in, out := &in.ExtAttrs, &out.ExtAttrs
		*out = new(string)
		**out = **in
	}
	if in.Fqdn != nil {
		in, out := &in.Fqdn, &out.Fqdn
		*out = new(string)
		**out = **in
	}
	if in.IPv4Addr != nil {
		in, out := &in.IPv4Addr, &out.IPv4Addr
		*out = new(string)
		**out = **in
	}
	if in.IPv4Cidr != nil {
		in, out := &in.IPv4Cidr, &out.IPv4Cidr
		*out = new(string)
		**out = **in
	}
	if in.IPv6Addr != nil {
		in, out := &in.IPv6Addr, &out.IPv6Addr
		*out = new(string)
		**out = **in
	}
	if in.IPv6Cidr != nil {
		in, out := &in.IPv6Cidr, &out.IPv6Cidr
		*out = new(string)
		**out = **in
	}
	if in.NetworkView != nil {
		in, out := &in.NetworkView, &out.NetworkView
		*out = new(string)
		**out = **in
	}
	if in.TTL != nil {
		in, out := &in.TTL, &out.TTL
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AllocationInitParameters.
func (in *AllocationInitParameters) DeepCopy() *AllocationInitParameters {
	if in == nil {
		return nil
	}
	out := new(AllocationInitParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AllocationList) DeepCopyInto(out *AllocationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Allocation, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AllocationList.
func (in *AllocationList) DeepCopy() *AllocationList {
	if in == nil {
		return nil
	}
	out := new(AllocationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AllocationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AllocationObservation) DeepCopyInto(out *AllocationObservation) {
	*out = *in
	if in.AllocatedIPv4Addr != nil {
		in, out := &in.AllocatedIPv4Addr, &out.AllocatedIPv4Addr
		*out = new(string)
		**out = **in
	}
	if in.AllocatedIPv6Addr != nil {
		in, out := &in.AllocatedIPv6Addr, &out.AllocatedIPv6Addr
		*out = new(string)
		**out = **in
	}
	if in.Comment != nil {
		in, out := &in.Comment, &out.Comment
		*out = new(string)
		**out = **in
	}
	if in.DNSView != nil {
		in, out := &in.DNSView, &out.DNSView
		*out = new(string)
		**out = **in
	}
	if in.EnableDNS != nil {
		in, out := &in.EnableDNS, &out.EnableDNS
		*out = new(bool)
		**out = **in
	}
	if in.ExtAttrs != nil {
		in, out := &in.ExtAttrs, &out.ExtAttrs
		*out = new(string)
		**out = **in
	}
	if in.Fqdn != nil {
		in, out := &in.Fqdn, &out.Fqdn
		*out = new(string)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.IPv4Addr != nil {
		in, out := &in.IPv4Addr, &out.IPv4Addr
		*out = new(string)
		**out = **in
	}
	if in.IPv4Cidr != nil {
		in, out := &in.IPv4Cidr, &out.IPv4Cidr
		*out = new(string)
		**out = **in
	}
	if in.IPv6Addr != nil {
		in, out := &in.IPv6Addr, &out.IPv6Addr
		*out = new(string)
		**out = **in
	}
	if in.IPv6Cidr != nil {
		in, out := &in.IPv6Cidr, &out.IPv6Cidr
		*out = new(string)
		**out = **in
	}
	if in.InternalID != nil {
		in, out := &in.InternalID, &out.InternalID
		*out = new(string)
		**out = **in
	}
	if in.NetworkView != nil {
		in, out := &in.NetworkView, &out.NetworkView
		*out = new(string)
		**out = **in
	}
	if in.Ref != nil {
		in, out := &in.Ref, &out.Ref
		*out = new(string)
		**out = **in
	}
	if in.TTL != nil {
		in, out := &in.TTL, &out.TTL
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AllocationObservation.
func (in *AllocationObservation) DeepCopy() *AllocationObservation {
	if in == nil {
		return nil
	}
	out := new(AllocationObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AllocationParameters) DeepCopyInto(out *AllocationParameters) {
	*out = *in
	if in.AllocatedIPv4Addr != nil {
		in, out := &in.AllocatedIPv4Addr, &out.AllocatedIPv4Addr
		*out = new(string)
		**out = **in
	}
	if in.AllocatedIPv6Addr != nil {
		in, out := &in.AllocatedIPv6Addr, &out.AllocatedIPv6Addr
		*out = new(string)
		**out = **in
	}
	if in.Comment != nil {
		in, out := &in.Comment, &out.Comment
		*out = new(string)
		**out = **in
	}
	if in.DNSView != nil {
		in, out := &in.DNSView, &out.DNSView
		*out = new(string)
		**out = **in
	}
	if in.EnableDNS != nil {
		in, out := &in.EnableDNS, &out.EnableDNS
		*out = new(bool)
		**out = **in
	}
	if in.ExtAttrs != nil {
		in, out := &in.ExtAttrs, &out.ExtAttrs
		*out = new(string)
		**out = **in
	}
	if in.Fqdn != nil {
		in, out := &in.Fqdn, &out.Fqdn
		*out = new(string)
		**out = **in
	}
	if in.IPv4Addr != nil {
		in, out := &in.IPv4Addr, &out.IPv4Addr
		*out = new(string)
		**out = **in
	}
	if in.IPv4Cidr != nil {
		in, out := &in.IPv4Cidr, &out.IPv4Cidr
		*out = new(string)
		**out = **in
	}
	if in.IPv6Addr != nil {
		in, out := &in.IPv6Addr, &out.IPv6Addr
		*out = new(string)
		**out = **in
	}
	if in.IPv6Cidr != nil {
		in, out := &in.IPv6Cidr, &out.IPv6Cidr
		*out = new(string)
		**out = **in
	}
	if in.NetworkView != nil {
		in, out := &in.NetworkView, &out.NetworkView
		*out = new(string)
		**out = **in
	}
	if in.TTL != nil {
		in, out := &in.TTL, &out.TTL
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AllocationParameters.
func (in *AllocationParameters) DeepCopy() *AllocationParameters {
	if in == nil {
		return nil
	}
	out := new(AllocationParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AllocationSpec) DeepCopyInto(out *AllocationSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
	in.InitProvider.DeepCopyInto(&out.InitProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AllocationSpec.
func (in *AllocationSpec) DeepCopy() *AllocationSpec {
	if in == nil {
		return nil
	}
	out := new(AllocationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AllocationStatus) DeepCopyInto(out *AllocationStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AllocationStatus.
func (in *AllocationStatus) DeepCopy() *AllocationStatus {
	if in == nil {
		return nil
	}
	out := new(AllocationStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Association) DeepCopyInto(out *Association) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Association.
func (in *Association) DeepCopy() *Association {
	if in == nil {
		return nil
	}
	out := new(Association)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Association) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AssociationInitParameters) DeepCopyInto(out *AssociationInitParameters) {
	*out = *in
	if in.Duid != nil {
		in, out := &in.Duid, &out.Duid
		*out = new(string)
		**out = **in
	}
	if in.EnableDHCP != nil {
		in, out := &in.EnableDHCP, &out.EnableDHCP
		*out = new(bool)
		**out = **in
	}
	if in.InternalID != nil {
		in, out := &in.InternalID, &out.InternalID
		*out = new(string)
		**out = **in
	}
	if in.MacAddr != nil {
		in, out := &in.MacAddr, &out.MacAddr
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AssociationInitParameters.
func (in *AssociationInitParameters) DeepCopy() *AssociationInitParameters {
	if in == nil {
		return nil
	}
	out := new(AssociationInitParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AssociationList) DeepCopyInto(out *AssociationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Association, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AssociationList.
func (in *AssociationList) DeepCopy() *AssociationList {
	if in == nil {
		return nil
	}
	out := new(AssociationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AssociationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AssociationObservation) DeepCopyInto(out *AssociationObservation) {
	*out = *in
	if in.Duid != nil {
		in, out := &in.Duid, &out.Duid
		*out = new(string)
		**out = **in
	}
	if in.EnableDHCP != nil {
		in, out := &in.EnableDHCP, &out.EnableDHCP
		*out = new(bool)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.InternalID != nil {
		in, out := &in.InternalID, &out.InternalID
		*out = new(string)
		**out = **in
	}
	if in.MacAddr != nil {
		in, out := &in.MacAddr, &out.MacAddr
		*out = new(string)
		**out = **in
	}
	if in.Ref != nil {
		in, out := &in.Ref, &out.Ref
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AssociationObservation.
func (in *AssociationObservation) DeepCopy() *AssociationObservation {
	if in == nil {
		return nil
	}
	out := new(AssociationObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AssociationParameters) DeepCopyInto(out *AssociationParameters) {
	*out = *in
	if in.Duid != nil {
		in, out := &in.Duid, &out.Duid
		*out = new(string)
		**out = **in
	}
	if in.EnableDHCP != nil {
		in, out := &in.EnableDHCP, &out.EnableDHCP
		*out = new(bool)
		**out = **in
	}
	if in.InternalID != nil {
		in, out := &in.InternalID, &out.InternalID
		*out = new(string)
		**out = **in
	}
	if in.MacAddr != nil {
		in, out := &in.MacAddr, &out.MacAddr
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AssociationParameters.
func (in *AssociationParameters) DeepCopy() *AssociationParameters {
	if in == nil {
		return nil
	}
	out := new(AssociationParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AssociationSpec) DeepCopyInto(out *AssociationSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
	in.InitProvider.DeepCopyInto(&out.InitProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AssociationSpec.
func (in *AssociationSpec) DeepCopy() *AssociationSpec {
	if in == nil {
		return nil
	}
	out := new(AssociationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AssociationStatus) DeepCopyInto(out *AssociationStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AssociationStatus.
func (in *AssociationStatus) DeepCopy() *AssociationStatus {
	if in == nil {
		return nil
	}
	out := new(AssociationStatus)
	in.DeepCopyInto(out)
	return out
}
