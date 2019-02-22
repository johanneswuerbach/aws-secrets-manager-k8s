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

func maybeUpdate(value string, updatedSecret hashedSecretRef) (bool, string) {
	changed := false
	matches := secretNameRegexp.FindStringSubmatch(value)

	if len(matches) == 3 && matches[1] == updatedSecret.name {
		changed = true
		value = updatedSecret.hashedName
	}

	return changed, value
}

func maybeUpdatePodTemplate(podTemplateSpec *corev1.PodTemplateSpec, updatedSecret hashedSecretRef) bool {
	pod := podTemplateSpec.Spec
	podSpecChanged := false

	if changed := maybeUpdateContainer(pod.InitContainers, updatedSecret); changed {
		podSpecChanged = changed
	}

	if changed := maybeUpdateContainer(pod.Containers, updatedSecret); changed {
		podSpecChanged = changed
	}

	for _, vol := range pod.Volumes {
		if vol.VolumeSource.Secret == nil {
			continue
		}

		if changed, value := maybeUpdate(vol.VolumeSource.Secret.SecretName, updatedSecret); changed {
			vol.VolumeSource.Secret.SecretName = value
			podSpecChanged = changed
		}
	}

	return podSpecChanged
}

func maybeUpdateContainer(containers []corev1.Container, updatedSecret hashedSecretRef) bool {
	containerChanged := false

	for _, container := range containers {
		for _, e := range container.Env {
			if e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
				continue
			}

			if changed, value := maybeUpdate(e.ValueFrom.SecretKeyRef.LocalObjectReference.Name, updatedSecret); changed {
				e.ValueFrom.SecretKeyRef.LocalObjectReference.Name = value
				containerChanged = true
			}
		}

		for _, e := range container.EnvFrom {
			if e.SecretRef == nil {
				continue
			}

			if changed, value := maybeUpdate(e.SecretRef.LocalObjectReference.Name, updatedSecret); changed {
				e.SecretRef.LocalObjectReference.Name = value
				containerChanged = true
			}
		}
	}

	return containerChanged
}
