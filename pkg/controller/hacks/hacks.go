package hacks

import (
	"context"
	"fmt"
	"strings"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/maistra/istio-operator/pkg/controller/common"
)

// CacheSyncWaitDuration is the how long the reconciler will skip reconciliation of a resource whose status was just
// updated to allow the event that was generated by the update to be received by the operator and update the cache.
var CacheSyncWaitDuration = 2 * time.Second

func WrapContext(ctx context.Context, earliestReconciliationTimes map[types.NamespacedName]time.Time) context.Context {
	return context.WithValue(ctx, "earliestReconciliationTimes", earliestReconciliationTimes)
}

// SkipReconciliationUntilCacheSynced prevents the object from being reconciled in the next 2 seconds. Call this
// function after you post an update to a resource if you want to reduce the likelihood of the reconcile() function
// being called again before the update comes back into the operator (until it does, any invocation of reconcile() will
// skip reconciliation and enqueue the object for reconciliation after the initial 2 second delay expires). This allows
// the watch event more time to come back and update the cache.
// While this 2s delay doesn't ensure that the cache is actually synced, it should improve 90% of cases.
// For the complete explanation, see https://issues.jboss.org/projects/MAISTRA/issues/MAISTRA-830 and
// https://issues.redhat.com/browse/MAISTRA-2047
func SkipReconciliationUntilCacheSynced(ctx context.Context, namespacedName types.NamespacedName) {
	// NOTE: storing earliestReconciliationTimes in ctx is wrong, but this is just a temporary hack
	earliestReconciliationTimes, ok := ctx.Value("earliestReconciliationTimes").(map[types.NamespacedName]time.Time)
	if !ok {
		panic("No earliestReconciliationTimes map in context; you must invoke hacks.WrapContext() before invoking hacks.SkipReconciliationUntilCacheSynced()")
	}
	earliestReconciliationTimes[namespacedName] = time.Now().Add(CacheSyncWaitDuration)
}

// RemoveTypeObjectFieldsFromCRDSchema works around the problem where OpenShift 3.11 doesn't like "type: object"
// in CRD OpenAPI schemas. This function removes all occurrences from the schema.
func RemoveTypeObjectFieldsFromCRDSchema(ctx context.Context, crd *apiextensionsv1beta1.CustomResourceDefinition) error {
	log := common.LogFromContext(ctx)
	log.Info("The API server rejected the CRD. Removing type:object fields from the CRD schema and trying again.")

	if crd.Spec.Validation == nil || crd.Spec.Validation.OpenAPIV3Schema == nil {
		return fmt.Errorf("Could not remove type:object fields from CRD schema as no spec.validation.openAPIV3Schema exists")
	}
	removeTypeObjectField(crd.Spec.Validation.OpenAPIV3Schema)
	return nil
}

// IsTypeObjectProblemInCRDSchemas returns true if the error provided is the error usually
// returned by the API server when it doesn't like "type:object" fields in the CRD's OpenAPI Schema.
func IsTypeObjectProblemInCRDSchemas(err error) bool {
	return err != nil && strings.Contains(err.Error(), "must only have \"properties\", \"required\" or \"description\" at the root if the status subresource is enabled")
}

// PatchUpV1beta1CRDs ensures required fields/settings are present, so v1
// conversion results in a valid CRD
func PatchUpV1beta1CRDs(crd *apiextensionsv1beta1.CustomResourceDefinition) {
	// ensure a schema exists
	ensureSchemaExists(crd)
}

func ensureSchemaExists(crd *apiextensionsv1beta1.CustomResourceDefinition) {
	if crd.Spec.Validation != nil && crd.Spec.Validation.OpenAPIV3Schema != nil {
		return
	}
	hasVersionSchema := false
	for _, version := range crd.Spec.Versions {
		hasVersionSchema = hasVersionSchema || (version.Schema != nil && version.Schema.OpenAPIV3Schema != nil)
	}
	if hasVersionSchema {
		for index, version := range crd.Spec.Versions {
			// make sure every version has a schema
			if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
				preserveUnknownFields := true
				crd.Spec.Versions[index].Schema = &apiextensionsv1beta1.CustomResourceValidation{
					OpenAPIV3Schema: &apiextensionsv1beta1.JSONSchemaProps{
						Type:                   "object",
						XPreserveUnknownFields: &preserveUnknownFields,
					},
				}
			}
		}
	} else {
		// create a common schema
		preserveUnknownFields := true
		crd.Spec.Validation = &apiextensionsv1beta1.CustomResourceValidation{
			OpenAPIV3Schema: &apiextensionsv1beta1.JSONSchemaProps{
				Type:                   "object",
				XPreserveUnknownFields: &preserveUnknownFields,
			},
		}
	}
}

// PreserveUnknownFields sets PreserveUnknownFields to false and adds
// x-kubernetes-preserve-unknown-fields to any object type definitions that have
// no properties or additionalProperties.  We do not check PreserveUnknownFields
// as older CRDs may not have it set.  We need to make sure all fields without
// a schema are marked with x-kubernetes-preserve-unknown-fields.
func PreserveUnknownFields(crd *apiextensionsv1.CustomResourceDefinition) {
	for index, version := range crd.Spec.Versions {
		if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
			continue
		}
		preserveUnknownFields(crd.Spec.Versions[index].Schema.OpenAPIV3Schema, true)
	}
	crd.Spec.PreserveUnknownFields = false
}

func preserveUnknownFields(schema *apiextensionsv1.JSONSchemaProps, root bool) {
	preserveFields := true
	for key, val := range schema.Properties {
		if root && key == "metadata" {
			// do not set XPreserveUnknownFields for root metadata field
			continue
		}
		switch val.Type {
		case "object":
			if len(val.Properties) == 0 {
				if val.AdditionalProperties == nil || val.AdditionalProperties.Schema == nil {
					val.XPreserveUnknownFields = &preserveFields
				}
			} else {
				preserveUnknownFields(&val, false)
			}
		case "array":
			if val.Items == nil || val.Items.Schema == nil {
				val.Items = &apiextensionsv1.JSONSchemaPropsOrArray{
					Schema: &apiextensionsv1.JSONSchemaProps{
						Type:                   "object",
						XPreserveUnknownFields: &preserveFields,
					},
				}
			} else {
				preserveUnknownFields(val.Items.Schema, false)
			}
		}
		schema.Properties[key] = val
	}
}

func removeTypeObjectField(schema *apiextensionsv1beta1.JSONSchemaProps) {
	if schema == nil {
		return
	}

	if schema.Type == "object" {
		schema.Type = ""
	}

	removeTypeObjectFieldFromArray(schema.OneOf)
	removeTypeObjectFieldFromArray(schema.AnyOf)
	removeTypeObjectFieldFromArray(schema.AllOf)
	removeTypeObjectFieldFromMap(schema.Properties)
	removeTypeObjectFieldFromMap(schema.PatternProperties)
	removeTypeObjectFieldFromMap(schema.Definitions)
	removeTypeObjectField(schema.Not)

	if schema.Items != nil {
		removeTypeObjectField(schema.Items.Schema)
		removeTypeObjectFieldFromArray(schema.Items.JSONSchemas)
	}
	if schema.AdditionalProperties != nil {
		removeTypeObjectField(schema.AdditionalProperties.Schema)
	}
	if schema.AdditionalItems != nil {
		removeTypeObjectField(schema.AdditionalItems.Schema)
	}
	for k, v := range schema.Dependencies {
		removeTypeObjectField(v.Schema)
		schema.Dependencies[k] = v
	}
}

func removeTypeObjectFieldFromArray(array []apiextensionsv1beta1.JSONSchemaProps) {
	for i, child := range array {
		removeTypeObjectField(&child)
		array[i] = child
	}
}

func removeTypeObjectFieldFromMap(m map[string]apiextensionsv1beta1.JSONSchemaProps) {
	for k, v := range m {
		removeTypeObjectField(&v)
		m[k] = v
	}
}
