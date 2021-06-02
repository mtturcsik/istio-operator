// +build !ignore_autogenerated

// Copyright Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"k8s.io/api/core/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Condition) DeepCopyInto(out *Condition) {
	*out = *in
	in.LastTransitionTime.DeepCopyInto(&out.LastTransitionTime)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Condition.
func (in *Condition) DeepCopy() *Condition {
	if in == nil {
		return nil
	}
	out := new(Condition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentStatus) DeepCopyInto(out *DeploymentStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentStatus.
func (in *DeploymentStatus) DeepCopy() *DeploymentStatus {
	if in == nil {
		return nil
	}
	out := new(DeploymentStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DiscoveryConnectionStatus) DeepCopyInto(out *DiscoveryConnectionStatus) {
	*out = *in
	in.LastConnected.DeepCopyInto(&out.LastConnected)
	in.LastEvent.DeepCopyInto(&out.LastEvent)
	in.LastFullSync.DeepCopyInto(&out.LastFullSync)
	in.LastDisconnect.DeepCopyInto(&out.LastDisconnect)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DiscoveryConnectionStatus.
func (in *DiscoveryConnectionStatus) DeepCopy() *DiscoveryConnectionStatus {
	if in == nil {
		return nil
	}
	out := new(DiscoveryConnectionStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DiscoveryRemoteStatus) DeepCopyInto(out *DiscoveryRemoteStatus) {
	*out = *in
	in.DiscoveryConnectionStatus.DeepCopyInto(&out.DiscoveryConnectionStatus)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DiscoveryRemoteStatus.
func (in *DiscoveryRemoteStatus) DeepCopy() *DiscoveryRemoteStatus {
	if in == nil {
		return nil
	}
	out := new(DiscoveryRemoteStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DiscoveryWatchStatus) DeepCopyInto(out *DiscoveryWatchStatus) {
	*out = *in
	in.DiscoveryConnectionStatus.DeepCopyInto(&out.DiscoveryConnectionStatus)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DiscoveryWatchStatus.
func (in *DiscoveryWatchStatus) DeepCopy() *DiscoveryWatchStatus {
	if in == nil {
		return nil
	}
	out := new(DiscoveryWatchStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FederationStatus) DeepCopyInto(out *FederationStatus) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FederationStatus.
func (in *FederationStatus) DeepCopy() *FederationStatus {
	if in == nil {
		return nil
	}
	out := new(FederationStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FederationStatus) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FederationStatusDetails) DeepCopyInto(out *FederationStatusDetails) {
	*out = *in
	if in.Exports != nil {
		in, out := &in.Exports, &out.Exports
		*out = make([]MeshServiceMapping, len(*in))
		copy(*out, *in)
	}
	if in.Imports != nil {
		in, out := &in.Imports, &out.Imports
		*out = make([]MeshServiceMapping, len(*in))
		copy(*out, *in)
	}
	in.Discovery.DeepCopyInto(&out.Discovery)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FederationStatusDetails.
func (in *FederationStatusDetails) DeepCopy() *FederationStatusDetails {
	if in == nil {
		return nil
	}
	out := new(FederationStatusDetails)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FederationStatusList) DeepCopyInto(out *FederationStatusList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]FederationStatus, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FederationStatusList.
func (in *FederationStatusList) DeepCopy() *FederationStatusList {
	if in == nil {
		return nil
	}
	out := new(FederationStatusList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FederationStatusList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FederationStatusSpec) DeepCopyInto(out *FederationStatusSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FederationStatusSpec.
func (in *FederationStatusSpec) DeepCopy() *FederationStatusSpec {
	if in == nil {
		return nil
	}
	out := new(FederationStatusSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FederationStatusStatus) DeepCopyInto(out *FederationStatusStatus) {
	*out = *in
	if in.Meshes != nil {
		in, out := &in.Meshes, &out.Meshes
		*out = make([]FederationStatusDetails, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FederationStatusStatus.
func (in *FederationStatusStatus) DeepCopy() *FederationStatusStatus {
	if in == nil {
		return nil
	}
	out := new(FederationStatusStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshDiscoveryStatus) DeepCopyInto(out *MeshDiscoveryStatus) {
	*out = *in
	if in.Remotes != nil {
		in, out := &in.Remotes, &out.Remotes
		*out = make([]DiscoveryRemoteStatus, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	in.Watch.DeepCopyInto(&out.Watch)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshDiscoveryStatus.
func (in *MeshDiscoveryStatus) DeepCopy() *MeshDiscoveryStatus {
	if in == nil {
		return nil
	}
	out := new(MeshDiscoveryStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshFederation) DeepCopyInto(out *MeshFederation) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshFederation.
func (in *MeshFederation) DeepCopy() *MeshFederation {
	if in == nil {
		return nil
	}
	out := new(MeshFederation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshFederation) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshFederationGateway) DeepCopyInto(out *MeshFederationGateway) {
	*out = *in
	in.Resources.DeepCopyInto(&out.Resources)
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Affinity != nil {
		in, out := &in.Affinity, &out.Affinity
		*out = new(v1.Affinity)
		(*in).DeepCopyInto(*out)
	}
	if in.Tolerations != nil {
		in, out := &in.Tolerations, &out.Tolerations
		*out = make([]v1.Toleration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshFederationGateway.
func (in *MeshFederationGateway) DeepCopy() *MeshFederationGateway {
	if in == nil {
		return nil
	}
	out := new(MeshFederationGateway)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshFederationGateways) DeepCopyInto(out *MeshFederationGateways) {
	*out = *in
	out.Ingress = in.Ingress
	out.Egress = in.Egress
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshFederationGateways.
func (in *MeshFederationGateways) DeepCopy() *MeshFederationGateways {
	if in == nil {
		return nil
	}
	out := new(MeshFederationGateways)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshFederationList) DeepCopyInto(out *MeshFederationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]MeshFederation, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshFederationList.
func (in *MeshFederationList) DeepCopy() *MeshFederationList {
	if in == nil {
		return nil
	}
	out := new(MeshFederationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshFederationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshFederationSecurity) DeepCopyInto(out *MeshFederationSecurity) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshFederationSecurity.
func (in *MeshFederationSecurity) DeepCopy() *MeshFederationSecurity {
	if in == nil {
		return nil
	}
	out := new(MeshFederationSecurity)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshFederationSpec) DeepCopyInto(out *MeshFederationSpec) {
	*out = *in
	out.Gateways = in.Gateways
	if in.Security != nil {
		in, out := &in.Security, &out.Security
		*out = new(MeshFederationSecurity)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshFederationSpec.
func (in *MeshFederationSpec) DeepCopy() *MeshFederationSpec {
	if in == nil {
		return nil
	}
	out := new(MeshFederationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshFederationStatus) DeepCopyInto(out *MeshFederationStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshFederationStatus.
func (in *MeshFederationStatus) DeepCopy() *MeshFederationStatus {
	if in == nil {
		return nil
	}
	out := new(MeshFederationStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshServiceMapping) DeepCopyInto(out *MeshServiceMapping) {
	*out = *in
	out.LocalService = in.LocalService
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshServiceMapping.
func (in *MeshServiceMapping) DeepCopy() *MeshServiceMapping {
	if in == nil {
		return nil
	}
	out := new(MeshServiceMapping)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceExportRule) DeepCopyInto(out *ServiceExportRule) {
	*out = *in
	if in.LabelSelector != nil {
		in, out := &in.LabelSelector, &out.LabelSelector
		*out = new(ServiceImportExportLabelelector)
		(*in).DeepCopyInto(*out)
	}
	if in.NameSelector != nil {
		in, out := &in.NameSelector, &out.NameSelector
		*out = new(ServiceNameMapping)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceExportRule.
func (in *ServiceExportRule) DeepCopy() *ServiceExportRule {
	if in == nil {
		return nil
	}
	out := new(ServiceExportRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceExportStatus) DeepCopyInto(out *ServiceExportStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceExportStatus.
func (in *ServiceExportStatus) DeepCopy() *ServiceExportStatus {
	if in == nil {
		return nil
	}
	out := new(ServiceExportStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceExports) DeepCopyInto(out *ServiceExports) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceExports.
func (in *ServiceExports) DeepCopy() *ServiceExports {
	if in == nil {
		return nil
	}
	out := new(ServiceExports)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ServiceExports) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceExportsList) DeepCopyInto(out *ServiceExportsList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ServiceExports, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceExportsList.
func (in *ServiceExportsList) DeepCopy() *ServiceExportsList {
	if in == nil {
		return nil
	}
	out := new(ServiceExportsList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ServiceExportsList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceExportsSpec) DeepCopyInto(out *ServiceExportsSpec) {
	*out = *in
	if in.Exports != nil {
		in, out := &in.Exports, &out.Exports
		*out = make([]ServiceExportRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceExportsSpec.
func (in *ServiceExportsSpec) DeepCopy() *ServiceExportsSpec {
	if in == nil {
		return nil
	}
	out := new(ServiceExportsSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceImportExportLabelelector) DeepCopyInto(out *ServiceImportExportLabelelector) {
	*out = *in
	in.Selector.DeepCopyInto(&out.Selector)
	if in.Aliases != nil {
		in, out := &in.Aliases, &out.Aliases
		*out = make([]ServiceNameMapping, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceImportExportLabelelector.
func (in *ServiceImportExportLabelelector) DeepCopy() *ServiceImportExportLabelelector {
	if in == nil {
		return nil
	}
	out := new(ServiceImportExportLabelelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceImportRule) DeepCopyInto(out *ServiceImportRule) {
	*out = *in
	if in.NameSelector != nil {
		in, out := &in.NameSelector, &out.NameSelector
		*out = new(ServiceNameMapping)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceImportRule.
func (in *ServiceImportRule) DeepCopy() *ServiceImportRule {
	if in == nil {
		return nil
	}
	out := new(ServiceImportRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceImports) DeepCopyInto(out *ServiceImports) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceImports.
func (in *ServiceImports) DeepCopy() *ServiceImports {
	if in == nil {
		return nil
	}
	out := new(ServiceImports)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ServiceImports) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceImportsList) DeepCopyInto(out *ServiceImportsList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ServiceImports, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceImportsList.
func (in *ServiceImportsList) DeepCopy() *ServiceImportsList {
	if in == nil {
		return nil
	}
	out := new(ServiceImportsList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ServiceImportsList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceImportsSpec) DeepCopyInto(out *ServiceImportsSpec) {
	*out = *in
	if in.Imports != nil {
		in, out := &in.Imports, &out.Imports
		*out = make([]ServiceImportRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceImportsSpec.
func (in *ServiceImportsSpec) DeepCopy() *ServiceImportsSpec {
	if in == nil {
		return nil
	}
	out := new(ServiceImportsSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceImportsStatus) DeepCopyInto(out *ServiceImportsStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceImportsStatus.
func (in *ServiceImportsStatus) DeepCopy() *ServiceImportsStatus {
	if in == nil {
		return nil
	}
	out := new(ServiceImportsStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceKey) DeepCopyInto(out *ServiceKey) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceKey.
func (in *ServiceKey) DeepCopy() *ServiceKey {
	if in == nil {
		return nil
	}
	out := new(ServiceKey)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceMeshExtension) DeepCopyInto(out *ServiceMeshExtension) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceMeshExtension.
func (in *ServiceMeshExtension) DeepCopy() *ServiceMeshExtension {
	if in == nil {
		return nil
	}
	out := new(ServiceMeshExtension)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ServiceMeshExtension) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceMeshExtensionList) DeepCopyInto(out *ServiceMeshExtensionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ServiceMeshExtension, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceMeshExtensionList.
func (in *ServiceMeshExtensionList) DeepCopy() *ServiceMeshExtensionList {
	if in == nil {
		return nil
	}
	out := new(ServiceMeshExtensionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ServiceMeshExtensionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceMeshExtensionSpec) DeepCopyInto(out *ServiceMeshExtensionSpec) {
	*out = *in
	if in.ImagePullSecrets != nil {
		in, out := &in.ImagePullSecrets, &out.ImagePullSecrets
		*out = make([]v1.LocalObjectReference, len(*in))
		copy(*out, *in)
	}
	in.WorkloadSelector.DeepCopyInto(&out.WorkloadSelector)
	if in.Phase != nil {
		in, out := &in.Phase, &out.Phase
		*out = new(FilterPhase)
		**out = **in
	}
	if in.Priority != nil {
		in, out := &in.Priority, &out.Priority
		*out = new(int)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceMeshExtensionSpec.
func (in *ServiceMeshExtensionSpec) DeepCopy() *ServiceMeshExtensionSpec {
	if in == nil {
		return nil
	}
	out := new(ServiceMeshExtensionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceMeshExtensionStatus) DeepCopyInto(out *ServiceMeshExtensionStatus) {
	*out = *in
	out.Deployment = in.Deployment
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceMeshExtensionStatus.
func (in *ServiceMeshExtensionStatus) DeepCopy() *ServiceMeshExtensionStatus {
	if in == nil {
		return nil
	}
	out := new(ServiceMeshExtensionStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceName) DeepCopyInto(out *ServiceName) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceName.
func (in *ServiceName) DeepCopy() *ServiceName {
	if in == nil {
		return nil
	}
	out := new(ServiceName)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServiceNameMapping) DeepCopyInto(out *ServiceNameMapping) {
	*out = *in
	out.Name = in.Name
	if in.Alias != nil {
		in, out := &in.Alias, &out.Alias
		*out = new(ServiceName)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceNameMapping.
func (in *ServiceNameMapping) DeepCopy() *ServiceNameMapping {
	if in == nil {
		return nil
	}
	out := new(ServiceNameMapping)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkloadSelector) DeepCopyInto(out *WorkloadSelector) {
	*out = *in
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkloadSelector.
func (in *WorkloadSelector) DeepCopy() *WorkloadSelector {
	if in == nil {
		return nil
	}
	out := new(WorkloadSelector)
	in.DeepCopyInto(out)
	return out
}
