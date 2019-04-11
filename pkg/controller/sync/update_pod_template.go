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

import corev1 "k8s.io/api/core/v1"

func shouldUpdate(value string, updatedSecret hashedSecretRef) bool {
	matches := secretNameRegexp.FindStringSubmatch(value)
	if len(matches) == 3 && matches[1] == updatedSecret.name {
		return true
	}

	return false
}

func maybeUpdatePodTemplate(podTemplateSpec *corev1.PodTemplateSpec, updatedSecret hashedSecretRef) bool {
	pod := podTemplateSpec.Spec
	podSpecChanged := false

	allPodContainers := append(pod.InitContainers, pod.Containers...)
	for _, container := range allPodContainers {
		if maybeUpdateContainer(container, updatedSecret) {
			podSpecChanged = true
		}
	}

	for _, vol := range pod.Volumes {
		if vol.VolumeSource.Secret == nil {
			continue
		}

		if shouldUpdate(vol.VolumeSource.Secret.SecretName, updatedSecret) {
			vol.VolumeSource.Secret.SecretName = updatedSecret.hashedName
			podSpecChanged = true
		}
	}

	return podSpecChanged
}

func maybeUpdateContainer(container corev1.Container, updatedSecret hashedSecretRef) bool {
	containerChanged := false

	for _, e := range container.Env {
		if e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
			continue
		}

		if shouldUpdate(e.ValueFrom.SecretKeyRef.LocalObjectReference.Name, updatedSecret) {
			e.ValueFrom.SecretKeyRef.LocalObjectReference.Name = updatedSecret.hashedName
			containerChanged = true
		}
	}

	for _, e := range container.EnvFrom {
		if e.SecretRef == nil {
			continue
		}

		if shouldUpdate(e.SecretRef.LocalObjectReference.Name, updatedSecret) {
			e.SecretRef.LocalObjectReference.Name = updatedSecret.hashedName
			containerChanged = true
		}
	}

	return containerChanged
}
