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

func maybeUpdate(value string, secret fetchedSecret) (bool, string) {
	changed := false
	matches := secretNameRegexp.FindStringSubmatch(value)

	if len(matches) == 3 && matches[1] == secret.name {
		changed = true
		value = secret.hashedName
	}

	return changed, value
}

func maybeUpdatePodTemplate(podTemplateSpec *corev1.PodTemplateSpec, secrets []fetchedSecret) bool {
	pod := podTemplateSpec.Spec
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
