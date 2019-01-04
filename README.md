# aws-secrets-manager-k8s [![CircleCI](https://circleci.com/gh/johanneswuerbach/aws-secrets-manager-k8s.svg?style=svg)](https://circleci.com/gh/johanneswuerbach/aws-secrets-manager-k8s)

Sync [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) secrets into a Kubernetes
cluster.

## Problem statement

While [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) provides an API and various SDKs
to use it from within an application, it's either not possible or not wanted to modify any application to call AWS Secrets Manager directly.

The solution in this repository allows to sync secrets from AWS Secrets Manager into
[Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/) to make them accessible
via as [files or environment variables](https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets)
for applications.

## Implementation

The CRD implements a continuous reconcile loop for every sync instance:

1. List all secrets the AWS role can see
1. Filter out not allowed prefixes and namespaces
1. Convert them to hashed Kubernetes Secrets
1. Create the hashed Kubernetes Secrets
1. Update references to all managed secrets in
   1. Deployments
   1. StatefulSets
   1. CronJobs
1. Sleep for one minute and restart

![Flow](flow.png)

## Usage

Create an AWS Role with access to the AWS Secrets Manager secrets you want to sync.

The secret names should have the following format: `prefix/namespace/name`, with the prefix
being an arbitrary string (e.g. `production`, `staging`) and `namespace` reflecting the targeted
Kubernetes Namespace and `name` of the to be created Kubernetes Secret.

Before defining the actual sync config, deploy the manager and CRD definition using `make deploy` into your cluster.

After that setup the actual sync similar to:

```yaml
apiVersion: awssecretsmanager.johanneswuerbach.net/v1alpha1
kind: Sync
metadata:
  labels:
    controller-tools.k8s.io: "1.0"
  name: sync-sample
spec:
  awsRoleARN: aws-role-to-be-used
  prefix: production/
  namespaces:
  - "default"
  - "monitoring"
```

## Development

This project is developed using [kubebuilder](http://book.kubebuilder.io/) and follows the documented kubebuilder development workflow.
