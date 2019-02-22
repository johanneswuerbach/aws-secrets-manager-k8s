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
	"testing"
	"time"

	awssecretsmanagerv1alpha1 "github.com/johanneswuerbach/aws-secrets-manager-k8s/pkg/apis/awssecretsmanager/v1alpha1"
	"github.com/onsi/gomega"
	"golang.org/x/net/context"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

var c client.Client

var expectedRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "foo", Namespace: "default"}}
var secretName = "foo-52f272c84b"
var secretKey = types.NamespacedName{Name: secretName, Namespace: "default"}

const timeout = time.Second * 5

type mockedSecretsManager struct {
	secretsmanageriface.SecretsManagerAPI
}

func (m mockedSecretsManager) GetSecretValueWithContext(aws.Context, *secretsmanager.GetSecretValueInput, ...request.Option) (*secretsmanager.GetSecretValueOutput, error) {
	return &secretsmanager.GetSecretValueOutput{
		ARN:          aws.String("test-secret-arn"),
		Name:         aws.String("test-secret"),
		SecretString: aws.String("test"),
	}, nil
}

func (m mockedSecretsManager) DescribeSecretWithContext(aws.Context, *secretsmanager.DescribeSecretInput, ...request.Option) (*secretsmanager.DescribeSecretOutput, error) {
	return &secretsmanager.DescribeSecretOutput{
		ARN:  aws.String("test-secret-arn"),
		Name: aws.String("test-secret"),
	}, nil
}

func testReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileSync{
		Client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		newClient: func(awsRoleArn string) secretsmanageriface.SecretsManagerAPI {
			return &mockedSecretsManager{}
		},
	}
}

func TestReconcile(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	instance := &awssecretsmanagerv1alpha1.Sync{
		ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "default"},
		Spec: awssecretsmanagerv1alpha1.SyncSpec{
			AWSSecretARN: "aws-secret-arn",
			AWSRoleARN:   "test-role",
			Template: awssecretsmanagerv1alpha1.SecretTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"managed-by": "aws secrets manager",
					},
				},
			},
		},
	}

	// Setup the Manager and Controller.  Wrap the Controller Reconcile function so it writes each request to a
	// channel when it is finished.
	mgr, err := manager.New(cfg, manager.Options{})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	c = mgr.GetClient()

	recFn, requests := SetupTestReconcile(testReconciler(mgr))
	g.Expect(add(mgr, recFn)).NotTo(gomega.HaveOccurred())

	stopMgr, mgrStopped := StartTestManager(mgr, g)

	defer func() {
		close(stopMgr)
		mgrStopped.Wait()
	}()

	err = c.Create(context.TODO(), &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "default"},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"name": "foo"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"name": "foo"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						corev1.Container{
							Name:  "foo",
							Image: "test",
							Env: []corev1.EnvVar{
								corev1.EnvVar{
									Name: "test",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "test-secret-1234567890",
											},
											Key: "string",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// Create the Sync object and expect the Reconcile and Secret to be created
	err = c.Create(context.TODO(), instance)
	// The instance object may not be a valid object because it might be missing some required fields.
	// Please modify the instance object by adding required fields and then remove the following if statement.
	if apierrors.IsInvalid(err) {
		t.Logf("failed to create object, got an invalid object error: %v", err)
		return
	}
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer c.Delete(context.TODO(), instance)
	g.Eventually(requests, timeout).Should(gomega.Receive(gomega.Equal(expectedRequest)))

	secret := &corev1.Secret{}
	g.Eventually(func() error { return c.Get(context.TODO(), secretKey, secret) }, timeout).
		Should(gomega.Succeed())

	deployment := &appsv1.Deployment{}
	g.Eventually(func() error {
		return c.Get(context.TODO(), types.NamespacedName{Name: "foo", Namespace: "default"}, deployment)
	}, timeout).
		Should(gomega.Succeed())

	g.Expect(deployment.Spec.Template.Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.LocalObjectReference.Name).Should(gomega.Equal(secretName))

	// Manually delete Secret since GC isn't enabled in the test control plane
	g.Expect(c.Delete(context.TODO(), secret)).To(gomega.Succeed())

}
