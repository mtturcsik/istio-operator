package webhooks

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/go-logr/logr"
	pkgerrors "github.com/pkg/errors"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apixv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	clientapixv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	pttypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/json"
	clientcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	maistrav1 "github.com/maistra/istio-operator/pkg/apis/maistra/v1"
	maistrav2 "github.com/maistra/istio-operator/pkg/apis/maistra/v2"
	"github.com/maistra/istio-operator/pkg/controller/common"
	"github.com/maistra/istio-operator/pkg/controller/servicemesh/webhookca"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
)

// XXX: this entire file can be removed once ValidatingWebhookConfiguration and
// Service definitions are moved into the operator's CSV file.

var webhookFailurePolicy = admissionv1.Fail

const (
	webhookSecretName    = "maistra-operator-serving-cert"
	webhookConfigMapName = "maistra-operator-cabundle"
	webhookServiceName   = "maistra-admission-controller"
)

func retStr(inStr string) *string {
	return &inStr
}

func createWebhookResources(ctx context.Context, mgr manager.Manager, log logr.Logger, operatorNamespace string) error {
	cl, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		return pkgerrors.Wrap(err, "error creating k8s client")
	}

	log.Info("Creating Maistra webhook Service")
	if err := cl.Create(context.TODO(), newWebhookService(operatorNamespace)); err != nil {
		if errors.IsAlreadyExists(err) {
			log.Info("Maistra webhook Service already exists")
		} else {
			return pkgerrors.Wrap(err, "error creating Maistra webhook Service")
		}
	}

	log.Info("Creating Maistra webhook CA bundle ConfigMap")
	if err := cl.Create(context.TODO(), newCABundleConfigMap(operatorNamespace)); err != nil {
		if errors.IsAlreadyExists(err) {
			log.Info("Maistra webhook CA bundle ConfigMap already exists")
		} else {
			return pkgerrors.Wrap(err, "error creating Maistra webhook CA bundle ConfigMap")
		}
	}

	log.Info("Creating Maistra secret")
	if err := cl.Create(context.TODO(), newMaistraServingCertSecret(operatorNamespace)); err != nil {
		if errors.IsAlreadyExists(err) {
			log.Info("Maistra secret already exists")
		} else {
			return pkgerrors.Wrap(err, "error creating Maistra secret")
		}
	}

	log.Info("Creating Maistra webhook IngressResource")
	if err := cl.Create(context.TODO(), newIngressResource(operatorNamespace)); err != nil {
		if errors.IsAlreadyExists(err) {
			log.Info("Maistra webhook CA bundle ConfigMap already exists")
		} else {
			return pkgerrors.Wrap(err, "error creating Creating Maistra webhook IngressResource")
		}
	}

	log.Info("Creating Maistra ValidatingWebhookConfiguration")
	validatingWebhookConfiguration := newValidatingWebhookConfiguration(operatorNamespace)
	if err := cl.Create(context.TODO(), validatingWebhookConfiguration); err != nil {
		if errors.IsAlreadyExists(err) {
			// the cache is not available until the manager is started, so webhook update needs to be done during startup.
			log.Info("Updating existing Maistra ValidatingWebhookConfiguration")
			existing := &admissionv1.ValidatingWebhookConfiguration{}
			if err := cl.Get(context.TODO(), types.NamespacedName{Name: validatingWebhookConfiguration.GetName()}, existing); err != nil {
				return pkgerrors.Wrap(err, "error retrieving existing Maistra ValidatingWebhookConfiguration")
			}
			validatingWebhookConfiguration.SetResourceVersion(existing.GetResourceVersion())
			if err := cl.Update(context.TODO(), validatingWebhookConfiguration); err != nil {
				return pkgerrors.Wrap(err, "error updating existing Maistra ValidatingWebhookConfiguration")
			}
		} else {
			return err
		}
	}

	log.Info("Registering Maistra ValidatingWebhookConfiguration with CABundle reconciler")
	if err := webhookca.WebhookCABundleManagerInstance.ManageWebhookCABundle(
		validatingWebhookConfiguration,
		&webhookca.ConfigMapCABundleSource{
			Namespace:     operatorNamespace,
			ConfigMapName: webhookConfigMapName,
			Key:           common.ServiceCABundleKey,
		}); err != nil {
		return err
	}

	log.Info("Creating Maistra MutatingWebhookConfiguration")
	mutatingWebhookConfiguration := newMutatingWebhookConfiguration(operatorNamespace)
	if err := cl.Create(context.TODO(), mutatingWebhookConfiguration); err != nil {
		if errors.IsAlreadyExists(err) {
			// the cache is not available until the manager is started, so webhook update needs to be done during startup.
			log.Info("Updating existing Maistra MutatingWebhookConfiguration")
			existing := &admissionv1.MutatingWebhookConfiguration{}
			if err := cl.Get(context.TODO(), types.NamespacedName{Name: mutatingWebhookConfiguration.GetName()}, existing); err != nil {
				return pkgerrors.Wrap(err, "error retrieving existing Maistra MutatingWebhookConfiguration")
			}
			mutatingWebhookConfiguration.SetResourceVersion(existing.GetResourceVersion())
			if err := cl.Update(context.TODO(), mutatingWebhookConfiguration); err != nil {
				return pkgerrors.Wrap(err, "error updating existing Maistra MutatingWebhookConfiguration")
			}
		} else {
			return err
		}
	}

	log.Info("Registering Maistra MutatingWebhookConfiguration with CABundle reconciler")
	if err := webhookca.WebhookCABundleManagerInstance.ManageWebhookCABundle(
		mutatingWebhookConfiguration,
		&webhookca.ConfigMapCABundleSource{
			Namespace:     operatorNamespace,
			ConfigMapName: webhookConfigMapName,
			Key:           common.ServiceCABundleKey,
		}); err != nil {
		return err
	}

	log.Info("Adding conversion webhook to SMCP CRD")
	if apixclient, err := clientapixv1.NewForConfig(mgr.GetConfig()); err == nil {
		if crdPatchBytes, err := json.Marshal(map[string]interface{}{
			"spec": map[string]interface{}{
				"conversion": &apixv1.CustomResourceConversion{
					Strategy: apixv1.WebhookConverter,
					Webhook: &apixv1.WebhookConversion{
						ConversionReviewVersions: []string{"v1beta1"},
						ClientConfig: &apixv1.WebhookClientConfig{
							URL: retStr("https://operator.s6662a7df5619be4d9c83-a383e1dc466c308d41a756a1a66c2b6a-ce00.us-south.satellite.test.appdomain.cloud/convert-smcp"),
						},
					},
				},
			},
		}); err == nil {
			if smcpcrd, err := apixclient.CustomResourceDefinitions().Patch(ctx, webhookca.ServiceMeshControlPlaneCRDName,
				pttypes.MergePatchType, crdPatchBytes, metav1.PatchOptions{FieldManager: common.FinalizerName}); err == nil {
				log.Info("Registering Maistra ServiceMeshControlPlane CRD conversion webhook with CABundle reconciler")
				if err := webhookca.WebhookCABundleManagerInstance.ManageWebhookCABundle(
					smcpcrd,
					&webhookca.ConfigMapCABundleSource{
						Namespace:     operatorNamespace,
						ConfigMapName: webhookConfigMapName,
						Key:           common.ServiceCABundleKey,
					}); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			return err
		}
	} else {
		return err
	}

	// wait for secret to become available to prevent the operator from bouncing
	// we don't worry about any errors here, as the worst thing that will happen
	// is that the operator might restart.
	coreclient, err := clientcorev1.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Info("error occured creating client for watching Maistra webhook Secret")
		return nil
	}
	secretwatch, err := coreclient.Secrets(operatorNamespace).Watch(ctx, metav1.ListOptions{FieldSelector: fmt.Sprintf("metadata.name=%s", webhookSecretName)})
	if err != nil {
		log.Info("error occured creating watch for Maistra webhook Secret")
		return nil
	}
	func() {
		defer secretwatch.Stop()
		log.Info("Waiting for Maistra webhook Secret to become available")
		select {
		case <-secretwatch.ResultChan():
			log.Info("Maistra webhook Secret is now ready")
		case <-time.After(30 * time.Second):
			log.Info("timed out waiting for Maistra webhook Secret to become available")
		}
	}()

	configMapWatch, err := coreclient.ConfigMaps(operatorNamespace).Watch(ctx, metav1.ListOptions{FieldSelector: fmt.Sprintf("metadata.name=%s", webhookConfigMapName)})
	if err != nil {
		log.Info("error occured creating watch for Maistra webhook CA bundle ConfigMap")
		return nil
	}
	func() {
		defer configMapWatch.Stop()
		log.Info("Waiting for Maistra webhook CA bundle ConfigMap to become available")
		select {
		case <-configMapWatch.ResultChan():
			log.Info("Maistra webhook CA bundle ConfigMap is now ready")
		case <-time.After(30 * time.Second):
			log.Info("timed out waiting for Maistra webhook CA bundle ConfigMap to become available")
		}
	}()

	return nil
}

func ptrPathType(p networkingv1beta1.PathType) *networkingv1beta1.PathType {
	return &p
}

func generateRSAKeyPair() (privKeyPem string, certPem string) {
	var caPEM, serverCertPEM, serverPrivKeyPEM *bytes.Buffer
	// CA config
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization: []string{"ibm.com"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// CA private key
	caPrivKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
	}

	// Self signed CA certificate
	caBytes, err := x509.CreateCertificate(cryptorand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// PEM encode CA cert
	caPEM = new(bytes.Buffer)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	dnsNames := []string{"webhook-service",
		"webhook-service.default", "webhook-service.default.svc"}
	commonName := "webhook-service.default.svc"

	// server cert config
	cert := &x509.Certificate{
		DNSNames:     dnsNames,
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"ibm.com"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// server private key
	serverPrivKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
	}

	// sign the server cert
	serverCertBytes, err := x509.CreateCertificate(cryptorand.Reader, cert, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// PEM encode the  server cert and key
	serverCertPEM = new(bytes.Buffer)
	_ = pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	})

	serverPrivKeyPEM = new(bytes.Buffer)
	_ = pem.Encode(serverPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	})
	certPem = serverCertPEM.String()
	privKeyPem = serverPrivKeyPEM.String()
	return
}

func newMaistraServingCertSecret(namespace string) *corev1.Secret {
	privkey, cert := generateRSAKeyPair()
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "maistra-operator-serving-cert",
			Namespace: namespace,
		},
		StringData: map[string]string{
			"tls.crt": cert,
			"tls.key": privkey,
		},
		Type: corev1.SecretType("kubernetes.io/tls"),
	}
}

func newIngressResource(namespace string) *networkingv1beta1.Ingress {
	return &networkingv1beta1.Ingress{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Ingress",
			APIVersion: "networking.k8s.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "istio-operator-webhook",
			Namespace: namespace,
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":                  "public-iks-k8s-nginx",
				"nginx.ingress.kubernetes.io/backend-protocol": "HTTPS",
			},
		},

		Spec: networkingv1beta1.IngressSpec{
			TLS: []networkingv1beta1.IngressTLS{
				networkingv1beta1.IngressTLS{
					Hosts: []string{
						"operator.s6662a7df5619be4d9c83-a383e1dc466c308d41a756a1a66c2b6a-ce00.us-south.satellite.test.appdomain.cloud",
					},
					SecretName: "s6662a7df5619be4d9c83-a383e1dc466c308d41a756a1a66c2b6a-ce00",
				},
			},
			Rules: []networkingv1beta1.IngressRule{
				networkingv1beta1.IngressRule{
					Host: "operator.s6662a7df5619be4d9c83-a383e1dc466c308d41a756a1a66c2b6a-ce00.us-south.satellite.test.appdomain.cloud",
					IngressRuleValue: networkingv1beta1.IngressRuleValue{
						HTTP: &networkingv1beta1.HTTPIngressRuleValue{
							Paths: []networkingv1beta1.HTTPIngressPath{
								networkingv1beta1.HTTPIngressPath{
									Path:     "/",
									PathType: ptrPathType("Prefix"),
									Backend: networkingv1beta1.IngressBackend{
										ServicePort: intstr.IntOrString{
											Type:   intstr.Type(0),
											IntVal: 443,
										},
										ServiceName: "maistra-admission-controller",
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

func newWebhookService(namespace string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      webhookServiceName,
			Namespace: namespace,
			Annotations: map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": webhookSecretName,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"name": "istio-operator",
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "validation",
					Port:       443,
					TargetPort: intstr.FromInt(11999),
				},
			},
		},
	}
}

func newCABundleConfigMap(namespace string) *corev1.ConfigMap {
	ret, error := ioutil.ReadFile("/root/lets_cert.pem")
	if error != nil {
		fmt.Printf("dfjkdsf")
	}
	CAstring := string(ret)
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      webhookConfigMapName,
			Namespace: namespace,
			Annotations: map[string]string{
				"service.beta.openshift.io/inject-cabundle": "true",
			},
		},
		Data: map[string]string{
			"service-ca.crt": CAstring,
		},
	}
}

func newValidatingWebhookConfiguration(namespace string) *admissionv1.ValidatingWebhookConfiguration {
	noneSideEffects := admissionv1.SideEffectClassNone
	return &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s.servicemesh-resources.maistra.io", namespace),
			Annotations: map[string]string{
				"service.beta.openshift.io/inject-cabundle": "true",
			},
		},
		Webhooks: []admissionv1.ValidatingWebhook{
			{
				Name: "smcp.validation.maistra.io",
				Rules: rulesFor("servicemeshcontrolplanes",
					[]string{maistrav1.SchemeGroupVersion.Version, maistrav2.SchemeGroupVersion.Version},
					admissionv1.Create, admissionv1.Update),
				FailurePolicy:           &webhookFailurePolicy,
				SideEffects:             &noneSideEffects,
				AdmissionReviewVersions: []string{"v1beta1"},
				ClientConfig: admissionv1.WebhookClientConfig{
					URL: retStr("https://operator.s6662a7df5619be4d9c83-a383e1dc466c308d41a756a1a66c2b6a-ce00.us-south.satellite.test.appdomain.cloud/validate-smcp"),
				},
			},
			{
				Name: "smmr.validation.maistra.io",
				Rules: rulesFor("servicemeshmemberrolls",
					[]string{maistrav1.SchemeGroupVersion.Version}, admissionv1.Create, admissionv1.Update),
				FailurePolicy:           &webhookFailurePolicy,
				SideEffects:             &noneSideEffects,
				AdmissionReviewVersions: []string{"v1beta1"},
				ClientConfig: admissionv1.WebhookClientConfig{
					URL: retStr("https://operator.s6662a7df5619be4d9c83-a383e1dc466c308d41a756a1a66c2b6a-ce00.us-south.satellite.test.appdomain.cloud/validate-smmr"),
				},
			},
			{
				Name: "smm.validation.maistra.io",
				Rules: rulesFor("servicemeshmembers",
					[]string{maistrav1.SchemeGroupVersion.Version}, admissionv1.Create, admissionv1.Update),
				FailurePolicy:           &webhookFailurePolicy,
				SideEffects:             &noneSideEffects,
				AdmissionReviewVersions: []string{"v1beta1"},
				ClientConfig: admissionv1.WebhookClientConfig{
					URL: retStr("https://operator.s6662a7df5619be4d9c83-a383e1dc466c308d41a756a1a66c2b6a-ce00.us-south.satellite.test.appdomain.cloud/validate-smm"),
				},
			},
		},
	}
}

func newMutatingWebhookConfiguration(namespace string) *admissionv1.MutatingWebhookConfiguration {
	noneOnDryRunSideEffects := admissionv1.SideEffectClassNoneOnDryRun
	return &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s.servicemesh-resources.maistra.io", namespace),
			Annotations: map[string]string{
				"service.beta.openshift.io/inject-cabundle": "true",
			},
		},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name: "smcp.mutation.maistra.io",
				Rules: rulesFor("servicemeshcontrolplanes",
					[]string{maistrav1.SchemeGroupVersion.Version, maistrav2.SchemeGroupVersion.Version},
					admissionv1.Create, admissionv1.Update),
				FailurePolicy:           &webhookFailurePolicy,
				SideEffects:             &noneOnDryRunSideEffects,
				AdmissionReviewVersions: []string{"v1beta1"},
				ClientConfig: admissionv1.WebhookClientConfig{
					URL: retStr("https://operator.s6662a7df5619be4d9c83-a383e1dc466c308d41a756a1a66c2b6a-ce00.us-south.satellite.test.appdomain.cloud/mutate-smcp"),
				},
			},
			{
				Name: "smmr.mutation.maistra.io",
				Rules: rulesFor("servicemeshmemberrolls",
					[]string{maistrav1.SchemeGroupVersion.Version}, admissionv1.Create, admissionv1.Update),
				FailurePolicy:           &webhookFailurePolicy,
				SideEffects:             &noneOnDryRunSideEffects,
				AdmissionReviewVersions: []string{"v1beta1"},
				ClientConfig: admissionv1.WebhookClientConfig{
					URL: retStr("https://operator.s6662a7df5619be4d9c83-a383e1dc466c308d41a756a1a66c2b6a-ce00.us-south.satellite.test.appdomain.cloud/mutate-smmr"),
				},
			},
		},
	}
}

func rulesFor(resource string, versions []string, operations ...admissionv1.OperationType) []admissionv1.RuleWithOperations {
	return []admissionv1.RuleWithOperations{
		{
			Rule: admissionv1.Rule{
				APIGroups:   []string{maistrav1.SchemeGroupVersion.Group},
				APIVersions: versions,
				Resources:   []string{resource},
			},
			Operations: operations,
		},
	}
}
