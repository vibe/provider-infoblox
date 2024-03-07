// SPDX-FileCopyrightText: 2023 The Crossplane Authors <https://crossplane.io>
//
// SPDX-License-Identifier: Apache-2.0

/*
Copyright 2022 Upbound Inc.
*/

// Code generated by upjet. DO NOT EDIT.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

type RecordInitParameters struct {

	// The network address in cidr format under which record has to be created.
	Cidr *string `json:"cidr,omitempty" tf:"cidr,omitempty"`

	// A description about PTR record.
	Comment *string `json:"comment,omitempty" tf:"comment,omitempty"`

	// Dns View under which the zone has been created.
	DNSView *string `json:"dnsView,omitempty" tf:"dns_view,omitempty"`

	// The Extensible attributes of PTR record to be added/updated, as a map in JSON format
	ExtAttrs *string `json:"extAttrs,omitempty" tf:"ext_attrs,omitempty"`

	// IPv4/IPv6 address for record creation. Set the field with valid IP for static allocation. If to be dynamically allocated set cidr field
	IPAddr *string `json:"ipAddr,omitempty" tf:"ip_addr,omitempty"`

	// Network view name of NIOS server.
	NetworkView *string `json:"networkView,omitempty" tf:"network_view,omitempty"`

	// The domain name in FQDN to which the record should point to.
	Ptrdname *string `json:"ptrdname,omitempty" tf:"ptrdname,omitempty"`

	// The name of the DNS PTR record in FQDN format
	RecordName *string `json:"recordName,omitempty" tf:"record_name,omitempty"`

	// TTL attribute value for the record.
	TTL *float64 `json:"ttl,omitempty" tf:"ttl,omitempty"`
}

type RecordObservation struct {

	// The network address in cidr format under which record has to be created.
	Cidr *string `json:"cidr,omitempty" tf:"cidr,omitempty"`

	// A description about PTR record.
	Comment *string `json:"comment,omitempty" tf:"comment,omitempty"`

	// Dns View under which the zone has been created.
	DNSView *string `json:"dnsView,omitempty" tf:"dns_view,omitempty"`

	// The Extensible attributes of PTR record to be added/updated, as a map in JSON format
	ExtAttrs *string `json:"extAttrs,omitempty" tf:"ext_attrs,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	// IPv4/IPv6 address for record creation. Set the field with valid IP for static allocation. If to be dynamically allocated set cidr field
	IPAddr *string `json:"ipAddr,omitempty" tf:"ip_addr,omitempty"`

	// Network view name of NIOS server.
	NetworkView *string `json:"networkView,omitempty" tf:"network_view,omitempty"`

	// The domain name in FQDN to which the record should point to.
	Ptrdname *string `json:"ptrdname,omitempty" tf:"ptrdname,omitempty"`

	// The name of the DNS PTR record in FQDN format
	RecordName *string `json:"recordName,omitempty" tf:"record_name,omitempty"`

	// TTL attribute value for the record.
	TTL *float64 `json:"ttl,omitempty" tf:"ttl,omitempty"`
}

type RecordParameters struct {

	// The network address in cidr format under which record has to be created.
	// +kubebuilder:validation:Optional
	Cidr *string `json:"cidr,omitempty" tf:"cidr,omitempty"`

	// A description about PTR record.
	// +kubebuilder:validation:Optional
	Comment *string `json:"comment,omitempty" tf:"comment,omitempty"`

	// Dns View under which the zone has been created.
	// +kubebuilder:validation:Optional
	DNSView *string `json:"dnsView,omitempty" tf:"dns_view,omitempty"`

	// The Extensible attributes of PTR record to be added/updated, as a map in JSON format
	// +kubebuilder:validation:Optional
	ExtAttrs *string `json:"extAttrs,omitempty" tf:"ext_attrs,omitempty"`

	// IPv4/IPv6 address for record creation. Set the field with valid IP for static allocation. If to be dynamically allocated set cidr field
	// +kubebuilder:validation:Optional
	IPAddr *string `json:"ipAddr,omitempty" tf:"ip_addr,omitempty"`

	// Network view name of NIOS server.
	// +kubebuilder:validation:Optional
	NetworkView *string `json:"networkView,omitempty" tf:"network_view,omitempty"`

	// The domain name in FQDN to which the record should point to.
	// +kubebuilder:validation:Optional
	Ptrdname *string `json:"ptrdname,omitempty" tf:"ptrdname,omitempty"`

	// The name of the DNS PTR record in FQDN format
	// +kubebuilder:validation:Optional
	RecordName *string `json:"recordName,omitempty" tf:"record_name,omitempty"`

	// TTL attribute value for the record.
	// +kubebuilder:validation:Optional
	TTL *float64 `json:"ttl,omitempty" tf:"ttl,omitempty"`
}

// RecordSpec defines the desired state of Record
type RecordSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     RecordParameters `json:"forProvider"`
	// THIS IS A BETA FIELD. It will be honored
	// unless the Management Policies feature flag is disabled.
	// InitProvider holds the same fields as ForProvider, with the exception
	// of Identifier and other resource reference fields. The fields that are
	// in InitProvider are merged into ForProvider when the resource is created.
	// The same fields are also added to the terraform ignore_changes hook, to
	// avoid updating them after creation. This is useful for fields that are
	// required on creation, but we do not desire to update them after creation,
	// for example because of an external controller is managing them, like an
	// autoscaler.
	InitProvider RecordInitParameters `json:"initProvider,omitempty"`
}

// RecordStatus defines the observed state of Record.
type RecordStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        RecordObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Record is the Schema for the Records API. <no value>
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,infoblox}
type Record struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +kubebuilder:validation:XValidation:rule="!('*' in self.managementPolicies || 'Create' in self.managementPolicies || 'Update' in self.managementPolicies) || has(self.forProvider.ptrdname) || (has(self.initProvider) && has(self.initProvider.ptrdname))",message="spec.forProvider.ptrdname is a required parameter"
	Spec   RecordSpec   `json:"spec"`
	Status RecordStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RecordList contains a list of Records
type RecordList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Record `json:"items"`
}

// Repository type metadata.
var (
	Record_Kind             = "Record"
	Record_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Record_Kind}.String()
	Record_KindAPIVersion   = Record_Kind + "." + CRDGroupVersion.String()
	Record_GroupVersionKind = CRDGroupVersion.WithKind(Record_Kind)
)

func init() {
	SchemeBuilder.Register(&Record{}, &RecordList{})
}
