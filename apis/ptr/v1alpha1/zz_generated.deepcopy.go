//go:build !ignore_autogenerated

/*
Copyright 2022 Upbound Inc.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Record) DeepCopyInto(out *Record) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Record.
func (in *Record) DeepCopy() *Record {
	if in == nil {
		return nil
	}
	out := new(Record)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Record) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RecordInitParameters) DeepCopyInto(out *RecordInitParameters) {
	*out = *in
	if in.Cidr != nil {
		in, out := &in.Cidr, &out.Cidr
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
	if in.ExtAttrs != nil {
		in, out := &in.ExtAttrs, &out.ExtAttrs
		*out = new(string)
		**out = **in
	}
	if in.IPAddr != nil {
		in, out := &in.IPAddr, &out.IPAddr
		*out = new(string)
		**out = **in
	}
	if in.NetworkView != nil {
		in, out := &in.NetworkView, &out.NetworkView
		*out = new(string)
		**out = **in
	}
	if in.Ptrdname != nil {
		in, out := &in.Ptrdname, &out.Ptrdname
		*out = new(string)
		**out = **in
	}
	if in.RecordName != nil {
		in, out := &in.RecordName, &out.RecordName
		*out = new(string)
		**out = **in
	}
	if in.TTL != nil {
		in, out := &in.TTL, &out.TTL
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RecordInitParameters.
func (in *RecordInitParameters) DeepCopy() *RecordInitParameters {
	if in == nil {
		return nil
	}
	out := new(RecordInitParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RecordList) DeepCopyInto(out *RecordList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Record, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RecordList.
func (in *RecordList) DeepCopy() *RecordList {
	if in == nil {
		return nil
	}
	out := new(RecordList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RecordList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RecordObservation) DeepCopyInto(out *RecordObservation) {
	*out = *in
	if in.Cidr != nil {
		in, out := &in.Cidr, &out.Cidr
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
	if in.ExtAttrs != nil {
		in, out := &in.ExtAttrs, &out.ExtAttrs
		*out = new(string)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.IPAddr != nil {
		in, out := &in.IPAddr, &out.IPAddr
		*out = new(string)
		**out = **in
	}
	if in.NetworkView != nil {
		in, out := &in.NetworkView, &out.NetworkView
		*out = new(string)
		**out = **in
	}
	if in.Ptrdname != nil {
		in, out := &in.Ptrdname, &out.Ptrdname
		*out = new(string)
		**out = **in
	}
	if in.RecordName != nil {
		in, out := &in.RecordName, &out.RecordName
		*out = new(string)
		**out = **in
	}
	if in.TTL != nil {
		in, out := &in.TTL, &out.TTL
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RecordObservation.
func (in *RecordObservation) DeepCopy() *RecordObservation {
	if in == nil {
		return nil
	}
	out := new(RecordObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RecordParameters) DeepCopyInto(out *RecordParameters) {
	*out = *in
	if in.Cidr != nil {
		in, out := &in.Cidr, &out.Cidr
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
	if in.ExtAttrs != nil {
		in, out := &in.ExtAttrs, &out.ExtAttrs
		*out = new(string)
		**out = **in
	}
	if in.IPAddr != nil {
		in, out := &in.IPAddr, &out.IPAddr
		*out = new(string)
		**out = **in
	}
	if in.NetworkView != nil {
		in, out := &in.NetworkView, &out.NetworkView
		*out = new(string)
		**out = **in
	}
	if in.Ptrdname != nil {
		in, out := &in.Ptrdname, &out.Ptrdname
		*out = new(string)
		**out = **in
	}
	if in.RecordName != nil {
		in, out := &in.RecordName, &out.RecordName
		*out = new(string)
		**out = **in
	}
	if in.TTL != nil {
		in, out := &in.TTL, &out.TTL
		*out = new(float64)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RecordParameters.
func (in *RecordParameters) DeepCopy() *RecordParameters {
	if in == nil {
		return nil
	}
	out := new(RecordParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RecordSpec) DeepCopyInto(out *RecordSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
	in.InitProvider.DeepCopyInto(&out.InitProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RecordSpec.
func (in *RecordSpec) DeepCopy() *RecordSpec {
	if in == nil {
		return nil
	}
	out := new(RecordSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RecordStatus) DeepCopyInto(out *RecordStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RecordStatus.
func (in *RecordStatus) DeepCopy() *RecordStatus {
	if in == nil {
		return nil
	}
	out := new(RecordStatus)
	in.DeepCopyInto(out)
	return out
}
