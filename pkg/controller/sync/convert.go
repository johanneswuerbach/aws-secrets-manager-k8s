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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func convertToKubernetesNamespacedName(secretName string) (*types.NamespacedName, error) {
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

	return &types.NamespacedName{Name: name, Namespace: namespace}, nil
}

func convertToKubernetesSecret(secretName string, secret *secretsmanager.GetSecretValueOutput) (*corev1.Secret, error) {
	namespacedName, err := convertToKubernetesNamespacedName(secretName)
	if err != nil {
		return nil, err
	}

	meta := metav1.ObjectMeta{
		Name:      namespacedName.Name,
		Namespace: namespacedName.Namespace,
		Annotations: map[string]string{
			"aws-secrets-manager-version-id": aws.StringValue(secret.VersionId),
			"aws-secrets-manager-arn":        aws.StringValue(secret.ARN),
		},
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
