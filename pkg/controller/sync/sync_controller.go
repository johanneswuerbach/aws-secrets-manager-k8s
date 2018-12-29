/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sync

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	awssecretsmanagerv1alpha1 "github.com/johanneswuerbach/aws-secrets-manager-k8s/pkg/apis/awssecretsmanager/v1alpha1"
	hash "github.com/johanneswuerbach/aws-secrets-manager-k8s/pkg/util/hash"
	appsv1 "k8s.io/api/apps/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"

	e "github.com/pkg/errors"
)

var log = logf.Log.WithName("controller")

const (
	defaultPrefix = ""
)

var defaultLoopTime = 1 * time.Minute
var secretNameRegexp = regexp.MustCompile("(.*)-(\\w{10})")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new Sync Controller and adds it to the Manager with default RBAC. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	sess := session.New()

	return &ReconcileSync{
		Client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		newClient: func(awsRoleARN string) secretsmanageriface.SecretsManagerAPI {
			if awsRoleARN != "" {
				creds := stscreds.NewCredentials(sess, awsRoleARN)

				return secretsmanager.New(sess, &aws.Config{Credentials: creds})
			}

			return secretsmanager.New(sess)
		},
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("sync-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to Sync
	err = c.Watch(&source.Kind{Type: &awssecretsmanagerv1alpha1.Sync{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// Uncomment watch a Secret created by Sync - change this for objects you create
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &awssecretsmanagerv1alpha1.Sync{},
	})
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileSync{}

// ReconcileSync reconciles a Sync object
type ReconcileSync struct {
	client.Client
	scheme    *runtime.Scheme
	newClient func(string) secretsmanageriface.SecretsManagerAPI
}

type fetchedSecret struct {
	name       string
	hashedName string
	arn        string
}

// Reconcile reads that state of the cluster for a Sync object and makes changes based on the state read
// and what is in the Sync.Spec
// Automatically generate RBAC rules to allow the Controller to read and write Secrets
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=awssecretsmanager.johanneswuerbach.net,resources=syncs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=awssecretsmanager.johanneswuerbach.net,resources=syncs/status,verbs=get;update;patch
func (r *ReconcileSync) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	// TODO: Timeout
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // cancel when we are finished consuming integers

	// Fetch the Sync instance
	instance := &awssecretsmanagerv1alpha1.Sync{}
	err := r.Get(ctx, request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object not found, return.  Created objects are automatically garbage collected.
			// For additional cleanup logic use finalizers.
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	allowedNamespaces := []string{instance.Namespace}

	if len(instance.Spec.Namespaces) > 0 {
		allowedNamespaces = instance.Spec.Namespaces
	}

	svc := r.newClient(instance.Spec.AWSRoleARN)

	awsSecrets, err := listSecrets(ctx, svc)
	if err != nil {
		log.Error(err, "Failed listing secrets")
		return reconcile.Result{
			RequeueAfter: defaultLoopTime,
		}, nil
	}

	fetchedSecrets := map[string][]fetchedSecret{}

	for _, awsSecret := range awsSecrets {
		awsSecretARN := aws.StringValue(awsSecret.ARN)
		awsSecretName := aws.StringValue(awsSecret.Name)

		// Skip secrets not starting with Prefix
		// When adheering to the principle of least privilege the controller shouldn't have access
		// to those as it will never rendered them into kubernetes secrets
		if !strings.HasPrefix(awsSecretName, instance.Spec.Prefix) {
			log.Info("Skipping AWS Secrets Manager secret, not matching prefix.",
				"arn", awsSecretARN,
				"prefix", instance.Spec.Prefix,
				"name", awsSecretName)
			continue
		}

		awsSecretName = strings.TrimPrefix(awsSecretName, instance.Spec.Prefix)

		// TODO Fast path if "*" is allowed
		allowed := false
		for _, allowedNamespace := range allowedNamespaces {
			if allowedNamespace == "*" || strings.HasPrefix(awsSecretName, fmt.Sprintf("%s/", allowedNamespace)) {
				allowed = true
				break
			}
		}

		if !allowed {
			log.Info("Skipping AWS Secrets Manager secret, not allowed namespace.",
				"arn", awsSecretARN,
				"prefix", instance.Spec.Prefix,
				"name", awsSecretName)
			continue
		}

		// TODO Ideally only fetch the value when a new secret version has been found
		result, err := getSecretValue(ctx, svc, awsSecret.ARN)
		if err != nil {
			log.Error(err, "Failed getting secret value", "arn", awsSecretARN)
			continue
		}

		secret, err := convertToKubernetesSecret(awsSecretName, result)
		if err != nil {
			log.Error(err, "Failed converting secret", "arn", awsSecretARN)
			continue
		}

		if err := controllerutil.SetControllerReference(instance, secret, r.scheme); err != nil {
			log.Error(err, "Failed setting controller reference", "arn", awsSecretARN)
			continue
		}

		hash, err := hash.SecretHash(secret)
		if err != nil {
			log.Error(err, "Failed hashing secret", "arn", awsSecretARN)
			continue
		}
		plainSecretName := secret.Name
		secret.Name = fmt.Sprintf("%s-%s", secret.Name, hash)

		f := fetchedSecret{
			name:       plainSecretName,
			hashedName: secret.Name,
			arn:        awsSecretARN,
		}

		if secrets, ok := fetchedSecrets[secret.Namespace]; ok {
			fetchedSecrets[secret.Namespace] = append(secrets, f)
		} else {
			fetchedSecrets[secret.Namespace] = []fetchedSecret{f}
		}

		// Sanity check secret name
		if !secretNameRegexp.MatchString(secret.Name) {
			log.Error(fmt.Errorf("malformed secret name: %s", secret.Name), "malformed kubernetes secret name", "arn", awsSecretARN)
			continue
		}

		// Check if the Secret already exists
		found := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, found)
		if err != nil && errors.IsNotFound(err) {
			log.Info("Creating Secret", "namespace", secret.Namespace, "name", secret.Name, "arn", awsSecretARN)
			if err = r.Create(ctx, secret); err != nil {
				log.Error(err, "Failed to create kubernetes secret", "arn", awsSecretARN)
				continue
			}
		} else if err != nil {
			log.Error(err, "Failed to get kubernetes secret", "arn", awsSecretARN)
			continue
		}

		// Update the found secret and write the result back if there are any changes
		if !reflect.DeepEqual(secret, found) {
			found.Data = secret.Data
			log.Info("Updating Secret", "namespace", secret.Namespace, "name", secret.Name, "arn", awsSecretARN)

			if err = r.Update(ctx, found); err != nil {
				log.Error(err, "Failed to update kubernetes secret", "arn", awsSecretARN)
				continue
			}
		}
	}

	if err := r.updateDeployments(ctx, fetchedSecrets); err != nil {
		log.Error(err, "Failed to update deployments")
	}

	if err := r.updateStatefulSets(ctx, fetchedSecrets); err != nil {
		log.Error(err, "Failed to update statefulsets")
	}

	if err := r.updateCronjobs(ctx, fetchedSecrets); err != nil {
		log.Error(err, "Failed to update cronjobs")
	}

	// Periodically re-sync secrets
	return reconcile.Result{
		RequeueAfter: defaultLoopTime,
	}, nil
}

func (r *ReconcileSync) updateDeployments(ctx context.Context, fetchedSecrets map[string][]fetchedSecret) error {
	for namespace, secrets := range fetchedSecrets {
		deployments := &appsv1.DeploymentList{}
		if err := r.List(ctx, &client.ListOptions{Namespace: namespace}, deployments); err != nil {
			return err
		}

		for _, deployment := range deployments.Items {
			if changed := maybeUpdatePodSpec(&deployment.Spec.Template.Spec, secrets); changed {
				fmt.Print("\n", "UPDATE!")

				// TODO: Use https://github.com/kubernetes/client-go/blob/e6b0ffda95bb53fab6259ebc653a0bbd3e826d9d/examples/create-update-delete-deployment/main.go#L118

				if err := r.Update(ctx, &deployment); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (r *ReconcileSync) updateStatefulSets(ctx context.Context, fetchedSecrets map[string][]fetchedSecret) error {
	for namespace, secrets := range fetchedSecrets {
		statefulsets := &appsv1.StatefulSetList{}
		if err := r.List(ctx, &client.ListOptions{Namespace: namespace}, statefulsets); err != nil {
			return err
		}

		for _, statefulset := range statefulsets.Items {
			if changed := maybeUpdatePodSpec(&statefulset.Spec.Template.Spec, secrets); changed {

				if err := r.Update(ctx, &statefulset); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (r *ReconcileSync) updateCronjobs(ctx context.Context, fetchedSecrets map[string][]fetchedSecret) error {
	for namespace, secrets := range fetchedSecrets {
		cronjobs := &batchv1beta1.CronJobList{}
		if err := r.List(ctx, &client.ListOptions{Namespace: namespace}, cronjobs); err != nil {
			return err
		}

		for _, cronjob := range cronjobs.Items {
			if changed := maybeUpdatePodSpec(&cronjob.Spec.JobTemplate.Spec.Template.Spec, secrets); changed {

				if err := r.Update(ctx, &cronjob); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func maybeUpdate(value string, secret fetchedSecret) (bool, string) {
	changed := false
	matches := secretNameRegexp.FindStringSubmatch(value)

	if len(matches) == 3 && matches[1] == secret.name {
		changed = true
		value = secret.hashedName
	}

	return changed, value
}

func maybeUpdatePodSpec(pod *corev1.PodSpec, secrets []fetchedSecret) bool {
	podSpecChanged := false

	if changed := maybeUpdateContainer(pod.InitContainers, secrets); changed {
		podSpecChanged = changed
	}

	if changed := maybeUpdateContainer(pod.Containers, secrets); changed {
		podSpecChanged = changed
	}

	for _, vol := range pod.Volumes {
		if vol.VolumeSource.Secret == nil {
			continue
		}

		for _, secret := range secrets {
			if changed, value := maybeUpdate(vol.VolumeSource.Secret.SecretName, secret); changed {
				vol.VolumeSource.Secret.SecretName = value
				podSpecChanged = changed
			}
		}
	}

	return podSpecChanged
}

func maybeUpdateContainer(containers []corev1.Container, secrets []fetchedSecret) bool {
	containerChanged := false

	for _, container := range containers {
		for _, e := range container.Env {
			if e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
				continue
			}

			for _, secret := range secrets {
				if changed, value := maybeUpdate(e.ValueFrom.SecretKeyRef.LocalObjectReference.Name, secret); changed {
					e.ValueFrom.SecretKeyRef.LocalObjectReference.Name = value
					containerChanged = true
				}
			}
		}

		for _, e := range container.EnvFrom {
			if e.SecretRef == nil {
				continue
			}

			for _, secret := range secrets {
				if changed, value := maybeUpdate(e.SecretRef.LocalObjectReference.Name, secret); changed {
					e.SecretRef.LocalObjectReference.Name = value
					containerChanged = true
				}
			}
		}
	}

	return containerChanged
}

func getSecretValue(ctx context.Context, svc secretsmanageriface.SecretsManagerAPI, secretARN *string) (*secretsmanager.GetSecretValueOutput, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     secretARN,
		VersionStage: aws.String("AWSCURRENT"),
	}

	result, err := svc.GetSecretValueWithContext(ctx, input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, e.Wrapf(aerr.OrigErr(), "Failed getting secret value, code: %s, message: %s", aerr.Code(), aerr.Message())
		}

		return nil, e.Wrap(err, "Failed getting secret value")
	}

	return result, nil
}

func convertToKubernetesSecret(secretName string, secret *secretsmanager.GetSecretValueOutput) (*corev1.Secret, error) {
	parts := strings.Split(secretName, "/")

	var namespace string
	var name string

	if len(parts) == 1 {
		namespace = "default"
		name = parts[0]
	} else if len(parts) == 2 {
		namespace = parts[0]
		name = parts[1]
	} else {
		// TODO: Support namespace/name/(entry)?
		return nil, fmt.Errorf("failed to decode secret name \"%s\", more then two parts", secretName)
	}

	meta := metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
	}

	if secret.SecretString != nil {
		secretValue := []byte(aws.StringValue(secret.SecretString))

		var awsSecretMap map[string]interface{}
		if err := json.Unmarshal(secretValue, &awsSecretMap); err != nil {
			// Secret values might not be json, which is fine.
			data, err := base64Decode(secretValue)
			if err != nil {
				return nil, err
			}

			return &corev1.Secret{
				ObjectMeta: meta,
				Data: map[string][]byte{
					"string": data,
				},
			}, nil
		}

		k8sSecretMap := map[string][]byte{}
		for key, i := range awsSecretMap {
			var secretValue []byte

			switch value := i.(type) {
			case string:
				secretValue = []byte(value)
			default:
				jsonValue, err := json.Marshal(value)
				if err != nil {
					return nil, err
				}

				secretValue = jsonValue
			}

			data, err := base64Decode(secretValue)
			if err != nil {
				return nil, err
			}

			k8sSecretMap[key] = data
		}

		return &corev1.Secret{
			ObjectMeta: meta,
			Data:       k8sSecretMap,
		}, nil
	} else if len(secret.SecretBinary) > 0 {
		data, err := base64Decode(secret.SecretBinary)
		if err != nil {
			return nil, err
		}

		return &corev1.Secret{
			ObjectMeta: meta,
			Data: map[string][]byte{
				"binary": data,
			},
		}, nil
	} else {
		return nil, fmt.Errorf("secret does not include secret string or secret binary")
	}
}

func base64Decode(data []byte) ([]byte, error) {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	_, err := base64.StdEncoding.Decode(out, data)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func listSecrets(ctx context.Context, svc secretsmanageriface.SecretsManagerAPI) ([]*secretsmanager.SecretListEntry, error) {
	secrets := []*secretsmanager.SecretListEntry{}

	if err := svc.ListSecretsPagesWithContext(ctx, &secretsmanager.ListSecretsInput{}, func(page *secretsmanager.ListSecretsOutput, lastPage bool) bool {
		secrets = append(secrets, page.SecretList...)
		return lastPage
	}); err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, e.Wrapf(aerr.OrigErr(), "Failed listing secrets, code: %s, message: %s", aerr.Code(), aerr.Message())
		}

		return nil, e.Wrap(err, "Failed listing secrets")
	}

	return secrets, nil
}
