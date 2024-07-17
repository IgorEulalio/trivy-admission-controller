# Trivy Admission Controller

The Trivy Admission Controller is a Kubernetes admission controller designed to work in conjunction with Trivy in your CI/CD pipeline. Its primary goal is to prevent the deployment of unscanned images or images that fail security scans within the Kubernetes cluster. By leveraging ETCD and Custom Resource Definitions (CRDs) to store data, this solution does not require any external database.

## Features

- **Integration with Trivy**: Seamlessly integrates with Trivy to ensure images are scanned for vulnerabilities before being deployed.
- **Prevents Deployment of Vulnerable Images**: Blocks the deployment of images that fail security scans, ensuring only secure images are deployed.
- **CRD-based Storage**: Uses Kubernetes CRDs and ETCD for data storage, eliminating the need for external databases.
- **Easy to Deploy**: Can be easily deployed as part of your Kubernetes cluster.

## How It Works

1. **Admission Review**: When a new pod is created, the admission controller intercepts the request and retrieves the images to be used in the pod.
2. **Image Scan Check**: It checks if the image has already been scanned by querying the Kubernetes datastore.
3. **Scan with Trivy**: If the image has not been scanned or if the scan results are outdated, it triggers a Trivy scan.
4. **Store Results**: The results of the scan are stored using Kubernetes CRDs.
5. **Decision**: Based on the scan results, the controller allows or denies the deployment of the pod.

## Installation

### Prerequisites

- Kubernetes cluster
- Trivy installed and accessible within the cluster

### Deploy the Admission Controller

1. **Apply the CRD**

    ```sh
    kubectl apply -f crd.yaml
    ```

2. **Create Service Account, Role, and RoleBinding**

    ```yaml
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: trivy-ac-serviceaccount
      namespace: default
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      name: trivy-ac-role
      namespace: default
    rules:
    - apiGroups: ["trivyac.io"]
      resources: ["scannedimages"]
      verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata:
      name: trivy-ac-rolebinding
      namespace: default
    subjects:
    - kind: ServiceAccount
      name: trivy-ac-serviceaccount
      namespace: default
    roleRef:
      kind: Role
      name: trivy-ac-role
      apiGroup: rbac.authorization.k8s.io
    ```

   Apply the configurations:

    ```sh
    kubectl apply -f serviceaccount.yaml
    kubectl apply -f role.yaml
    kubectl apply -f rolebinding.yaml
    ```

3. **Deploy the Admission Controller**

    ```yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: trivy-admission-controller
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: trivy-admission-controller
      template:
        metadata:
          labels:
            app: trivy-admission-controller
        spec:
          serviceAccountName: trivy-ac-serviceaccount
          containers:
          - name: trivy-admission-controller
            image: your-image-repo/trivy-admission-controller:latest
            ports:
            - containerPort: 8443
    ```

   Apply the deployment:

    ```sh
    kubectl apply -f chart.yaml
    ```

4. **Create the ValidatingWebhookConfiguration**

    ```yaml
    apiVersion: admissionregistration.k8s.io/v1
    kind: ValidatingWebhookConfiguration
    metadata:
      name: "trivy-admission-controller"
    webhooks:
      - name: "trivy.admissioncontroller.com"
        rules:
          - apiGroups:   [""]
            apiVersions: ["v1"]
            operations:  ["CREATE"]
            resources:   ["pods"]
            scope:       "Namespaced"
        clientConfig:
          service:
            namespace: "default"
            name: trivy-admission-controller
            path: /validate
            port: 8443
          caBundle: <your-ca-bundle>
        admissionReviewVersions: ["v1"]
        sideEffects: None
        timeoutSeconds: 5
    ```

   Apply the webhook configuration:

    ```sh
    kubectl apply -f webhook.yaml
    ```

## Usage

Once deployed, the Trivy Admission Controller will automatically intercept pod creation requests and ensure that the container images used have been scanned and do not contain vulnerabilities.

## Configuration

### Environment Variables

- `TRIVY_SERVER`: The URL of the Trivy server.
- `CACHE_TTL`: The time-to-live for cached scan results.

## Contributing

We welcome contributions! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License.
