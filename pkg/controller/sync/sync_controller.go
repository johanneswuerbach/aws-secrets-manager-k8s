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
	"fmt"
	"reflect"
	"regexp"
	"time"

	awssecretsmanagerv1alpha1 "github.com/johanneswuerbach/aws-secrets-manager-k8s/pkg/apis/awssecretsmanager/v1alpha1"
	hash "github.com/johanneswuerbach/aws-secrets-manager-k8s/pkg/util/hash"
	appsv1 "k8s.io/api/apps/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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

type hashedSecretRef struct {
	namespace  string
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

	awsSecretRole := instance.Spec.AWSRoleARN
	awsSecretARN := instance.Spec.AWSSecretARN

	svc := r.newClient(awsSecretRole)

	awsSecret, err := describeSecret(ctx, svc, instance.Spec.AWSSecretARN)
	if err != nil {
		log.Error(err, "Failed describing secret", "arn", awsSecretARN, "role", awsSecretRole)
		return reconcile.Result{
			RequeueAfter: defaultLoopTime,
		}, nil
	}

	// TODO Only fetch the value when a new secret version has been found
	result, err := getSecretValue(ctx, svc, awsSecret.ARN)
	if err != nil {
		log.Error(err, "Failed getting secret value", "arn", awsSecretARN)
		return reconcile.Result{
			RequeueAfter: defaultLoopTime,
		}, nil
	}

	secret, err := convertToKubernetesSecret(result, instance)
	if err != nil {
		log.Error(err, "Failed converting secret", "arn", awsSecretARN)
		return reconcile.Result{
			RequeueAfter: defaultLoopTime,
		}, nil
	}

	if err := controllerutil.SetControllerReference(instance, secret, r.scheme); err != nil {
		log.Error(err, "Failed setting controller reference", "arn", awsSecretARN)
		return reconcile.Result{
			RequeueAfter: defaultLoopTime,
		}, nil
	}

	hash, err := hash.SecretHash(secret)
	if err != nil {
		log.Error(err, "Failed hashing secret", "arn", awsSecretARN)
	}
	plainSecretName := secret.Name
	secret.Name = fmt.Sprintf("%s-%s", secret.Name, hash)

	updatedSecret := hashedSecretRef{
		namespace:  secret.Namespace,
		name:       plainSecretName,
		hashedName: secret.Name,
		arn:        awsSecretARN,
	}

	// Sanity check secret name
	if !secretNameRegexp.MatchString(secret.Name) {
		log.Error(fmt.Errorf("malformed secret name: %s", secret.Name), "malformed kubernetes secret name", "arn", awsSecretARN)
		return reconcile.Result{
			RequeueAfter: defaultLoopTime,
		}, nil
	}

	// Check if the Secret already exists
	found := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Secret", "namespace", secret.Namespace, "name", secret.Name, "arn", awsSecretARN)
		if err = r.Create(ctx, secret); err != nil {
			log.Error(err, "Failed to create kubernetes secret", "arn", awsSecretARN)
			return reconcile.Result{
				RequeueAfter: defaultLoopTime,
			}, nil
		}
	} else if err != nil {
		log.Error(err, "Failed to get kubernetes secret", "arn", awsSecretARN)
		return reconcile.Result{
			RequeueAfter: defaultLoopTime,
		}, nil
	}

	// Update the found secret and write the result back if there are any changes
	if !reflect.DeepEqual(secret, found) {
		found.Data = secret.Data
		log.Info("Updating Secret", "namespace", secret.Namespace, "name", secret.Name, "arn", awsSecretARN)

		if err = r.Update(ctx, found); err != nil {
			log.Error(err, "Failed to update kubernetes secret", "arn", awsSecretARN)
			return reconcile.Result{
				RequeueAfter: defaultLoopTime,
			}, nil
		}
	}

	if err := r.updateDeployments(ctx, updatedSecret); err != nil {
		log.Error(err, "Failed to update deployments")
	}

	if err := r.updateStatefulSets(ctx, updatedSecret); err != nil {
		log.Error(err, "Failed to update statefulsets")
	}

	if err := r.updateCronjobs(ctx, updatedSecret); err != nil {
		log.Error(err, "Failed to update cronjobs")
	}

	// Periodically re-sync secrets
	return reconcile.Result{
		RequeueAfter: defaultLoopTime,
	}, nil
}

func (r *ReconcileSync) updateDeployments(ctx context.Context, updatedSecret hashedSecretRef) error {
	deployments := &appsv1.DeploymentList{}
	if err := r.List(ctx, &client.ListOptions{Namespace: updatedSecret.namespace}, deployments); err != nil {
		return err
	}

	for _, deployment := range deployments.Items {
		if changed := maybeUpdatePodTemplate(&deployment.Spec.Template, updatedSecret); changed {

			// TODO: Use https://github.com/kubernetes/client-go/blob/e6b0ffda95bb53fab6259ebc653a0bbd3e826d9d/examples/create-update-delete-deployment/main.go#L118

			if err := r.Update(ctx, &deployment); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *ReconcileSync) updateStatefulSets(ctx context.Context, updatedSecret hashedSecretRef) error {
	statefulsets := &appsv1.StatefulSetList{}
	if err := r.List(ctx, &client.ListOptions{Namespace: updatedSecret.namespace}, statefulsets); err != nil {
		return err
	}

	for _, statefulset := range statefulsets.Items {
		if changed := maybeUpdatePodTemplate(&statefulset.Spec.Template, updatedSecret); changed {

			if err := r.Update(ctx, &statefulset); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *ReconcileSync) updateCronjobs(ctx context.Context, updatedSecret hashedSecretRef) error {
	cronjobs := &batchv1beta1.CronJobList{}
	if err := r.List(ctx, &client.ListOptions{Namespace: updatedSecret.namespace}, cronjobs); err != nil {
		return err
	}

	for _, cronjob := range cronjobs.Items {
		if changed := maybeUpdatePodTemplate(&cronjob.Spec.JobTemplate.Spec.Template, updatedSecret); changed {

			if err := r.Update(ctx, &cronjob); err != nil {
				return err
			}
		}
	}

	return nil
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

func describeSecret(ctx context.Context, svc secretsmanageriface.SecretsManagerAPI, secretARN string) (*secretsmanager.DescribeSecretOutput, error) {
	input := &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretARN),
	}

	result, err := svc.DescribeSecretWithContext(ctx, input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, e.Wrapf(aerr.OrigErr(), "Failed describing secret, code: %s, message: %s", aerr.Code(), aerr.Message())
		}

		return nil, e.Wrap(err, "Failed describing secret")
	}

	return result, nil
}
