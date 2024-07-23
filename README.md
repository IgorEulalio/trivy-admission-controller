# Trivy Admission Controller

The Trivy Admission Controller is a Kubernetes admission controller designed to work in conjunction with Trivy in your CI/CD pipeline. Its primary goal is to prevent the deployment of unscanned images or images that fail security scans within the Kubernetes cluster. By leveraging ETCD and Custom Resource Definitions (CRDs) to store data, this solution does not require any external database.

## Features

- **Integration with Trivy**: Seamlessly integrates with Trivy to ensure images are scanned for vulnerabilities before being deployed.
- **Prevents Deployment of Vulnerable Images**: Blocks the deployment of images that fail security scans, ensuring only secure images are deployed.
- **CRD-based Storage**: Uses Kubernetes CRDs and ETCD for data storage, eliminating the need for external databases.
- **Easy to Deploy**: Can be easily deployed as part of your Kubernetes cluster by using our helm chart.

## How It Works

1. **Scan image with trivy CLI in the pipeline**: Trivy is used in the pipeline and generates a JSON output.
2. **Call admission controller from the pipeline**: Call the admission controller with the JSON output from Trivy so the admission-controller can store the image in cache.
3. **Admission Review**: When a new pod is created, the Kube API server calls the webhook as per instructions in the [dynamic admission controller docs](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/), sending the AdmissionReview.
4. **Admission Review validation**: Here's where the main validation happens, the admission controller checks if the image has been scanned in the pipeline and is not outdated (purged from the cache). If the image has not been scanned or if the scan results are outdated, it triggers a Trivy scan. It returns allowed or denied based on this validation.
5. **Store Results**: The results of the scan are stored in ETCD and used if any following requests are made for the same image.
6. **Response**: The admission controller returns a response to the Kube API server, which then allows or denies the pod creation request based on the response.

![Architecture](docs/architecture.png?raw=true "Architecture")


## Installation

### Prerequisites

- Kubernetes cluster and access to deploy resources in it
- Helm

### Deploy the Admission Controller with Helm

1. **Deploy the helm chart**

    ```sh
    helm upgrade --install trivy-ac --namespace trivy-admission-controller --create-namespace ./
    ```

That should deploy the admission-controller in the trivy-admission-controller namespace along the CRDs and the service account.   

## Usage

Once deployed, the Trivy Admission Controller will automatically intercept pod creation requests and ensure that the container images used have been scanned and do not contain vulnerabilities.

## Configuration

There are two ways to configure the Trivy Admission Controller: environment variables and a config file.

### Environment Variables

- `trivy_path`: The path to the Trivy binary. Default is `/usr/local/bin/trivy`.
- `namespace`: The namespace where CRD from trivy-admission-controller will be created. Default is `trivy-admission-controller`.
- `kube_config`: Path to kube_config file, it should be used only in development. Default is `~/.kube/config`.
- `output_dir`: Output directory where the scan results will be stored. Default is `/tmp`.
- `cache.local.max_size`: Maximum number of image bytes to store in the cache. Default is `5000`.
- `cache.object_ttl`: Time to live for the cache object. Default is `1h (3600s)`.

### Config file

Example config file:
```yaml
kube_config: "$HOME/.kube/config"
port: 5001
output_dir: "./"
namespace: default
trivy_path: /opt/homebrew/bin/trivy
tls_cert_file: $HOME/certs/server.crt
tls_key_file: $HOME/certs/server.key
#cache:
#  redis:
#    port:
#    password:
#    database:
#  local:
#    expiration: 10
#    max_size: 100
```
## Contributing

We welcome contributions! Please open an issue or submit a pull request on GitHub.

## License

Trivy Admission Controller is licensed to you under the Apache 2.0 open source license.
