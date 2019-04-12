package sync

import (
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestGetReferencesToSecret(t *testing.T) {
	optional := false

	pts := corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				corev1.Container{
					Name:  "foo",
					Image: "test",
					Env: []corev1.EnvVar{
						corev1.EnvVar{
							Name: "yann",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "foo-1234567890",
									},
									Key: "string",
								},
							},
						},
					},
					EnvFrom: []corev1.EnvFromSource{
						corev1.EnvFromSource{
							SecretRef: &corev1.SecretEnvSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "foo-1234567890",
								},
								Optional: &optional,
							},
						},
					},
				},
			},
		},
	}

	updatedSecret := hashedSecretRef{
		namespace:  "default",
		name:       "foo",
		hashedName: "foo-9876543210",
	}

	maybeUpdatePodTemplate(&pts, updatedSecret)
	if pts.Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.LocalObjectReference.Name != updatedSecret.hashedName {
		t.Errorf("Pod Template Env was not updated!")
	}

	if pts.Spec.Containers[0].EnvFrom[0].SecretRef.LocalObjectReference.Name != updatedSecret.hashedName {
		t.Errorf("Pod Template EnvFrom was not updated!")
	}
}
