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

	awssecretsmanagerv1alpha1 "github.com/johanneswuerbach/aws-secrets-manager-k8s/pkg/apis/awssecretsmanager/v1alpha1"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func secretValueToKubernetesSecretData(secretValue []byte)(map[string][]byte, error) {
	awsSecretMap := make(map[string]interface{})

	if err := json.Unmarshal(secretValue, &awsSecretMap); err != nil {
		// Secret value is not a JSON
		data := base64Encode(secretValue)
		return map[string][]byte{
			"string": data,
		}, nil
	}

	// Secret value is a JSON
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

		data := base64Encode(secretValue)

		k8sSecretMap[key] = data
	}

	return k8sSecretMap, nil
}

func convertToKubernetesSecret(secret *secretsmanager.GetSecretValueOutput, instance *awssecretsmanagerv1alpha1.Sync) (*corev1.Secret, error) {
	k8sSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.ObjectMeta.Name,
			Namespace: instance.ObjectMeta.Namespace,
			Annotations: map[string]string{
				"aws-secrets-manager-version-id": aws.StringValue(secret.VersionId),
				"aws-secrets-manager-arn":        aws.StringValue(secret.ARN),
			},
		},
	}

	if secret.SecretString == nil {
		if len(secret.SecretBinary) == 0 {
			return nil, fmt.Errorf("secret does not include secret string or secret binary")
		}

		data := base64Encode(secret.SecretBinary)
		k8sSecret.Data = map[string][]byte{
			"binary": data,
		}
		return k8sSecret, nil
	}

	secretValue  := []byte(aws.StringValue(secret.SecretString))
	k8sSecretData, err := secretValueToKubernetesSecretData(secretValue)
	if err != nil {
		return nil, fmt.Errorf("failed processing secret: %s", err)
	}

	k8sSecret.Data = k8sSecretData
	return k8sSecret, nil
}

func base64Encode(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data))
}
