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

func secretHasName(value string, secretName string) bool {
	matches := secretNameRegexp.FindStringSubmatch(value)
	if len(matches) == 3 && matches[1] == secretName {
		return true
	}

	return false
}

func getReferencesToSecret(podTemplateSpec *corev1.PodTemplateSpec, secretName string) []*string {
	pod := podTemplateSpec.Spec
	var refs []*string

	allPodContainers := append(pod.InitContainers, pod.Containers...)

	for _, container := range allPodContainers {
		for _, e := range container.Env {
			if e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil {
				continue
			}

			if secretHasName(e.ValueFrom.SecretKeyRef.LocalObjectReference.Name, secretName) {
				refs = append(refs, &(e.ValueFrom.SecretKeyRef.LocalObjectReference.Name))
			}
		}

		for _, e := range container.EnvFrom {
			if e.SecretRef == nil {
				continue
			}

			if secretHasName(e.SecretRef.LocalObjectReference.Name, secretName) {
				refs = append(refs, &(e.SecretRef.LocalObjectReference.Name))
			}
		}
	}

	for _, volume := range pod.Volumes {
		if volume.VolumeSource.Secret == nil {
			continue
		}

		if secretHasName(volume.VolumeSource.Secret.SecretName, secretName) {
			refs = append(refs, &volume.VolumeSource.Secret.SecretName)
		}
	}

	return refs
}

func maybeUpdatePodTemplate(podTemplateSpec *corev1.PodTemplateSpec, updatedSecret hashedSecretRef) (changed bool) {
	refsToSecret := getReferencesToSecret(podTemplateSpec, updatedSecret.name)

	if len(refsToSecret) == 0 {
		return false
	}

	for _, ref := range refsToSecret {
		*ref = updatedSecret.hashedName
	}

	return true
}
