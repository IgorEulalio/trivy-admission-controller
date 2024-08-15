package kubernetes

import (
	"context"
	"flag"
	"fmt"
	"sync"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/config"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

const (
	ResourcePlural = "scannedimages"
)

type Client interface {
	GetSecret(namespace, secretName string) (*v1.Secret, error)
	GetResource(gvr schema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error)
}

type KubernetesClient struct {
	*k8s.Clientset
	RestConfig *rest.Config
	Dynamic    dynamic.Interface
}

func (c KubernetesClient) GetSecret(namespace, secretName string) (*v1.Secret, error) {
	secret, err := c.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s in namespace %s: %v", secretName, namespace, err)
	}
	return secret, nil
}

func (c KubernetesClient) GetResource(gvr schema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error) {
	resource, err := c.Dynamic.Resource(gvr).Namespace(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get resource %s in namespace %s: %v", name, namespace, err)
	}
	return resource, nil
}

var (
	client *KubernetesClient
	once   sync.Once
)

func Init() error {
	if client != nil {
		return nil
	}

	var initErr error

	once.Do(func() {
		client = new(KubernetesClient)
		configuration := config.Cfg
		var err error
		if configuration.KubeConfig != "" {
			client.RestConfig, err = clientcmd.BuildConfigFromFlags("", configuration.KubeConfig)
		} else {
			client.RestConfig, err = rest.InClusterConfig()
		}
		if err != nil {
			initErr = err
			return
		}

		client.Clientset, err = k8s.NewForConfig(client.RestConfig)
		if err != nil {
			initErr = err
			return
		}

		client.Dynamic, err = dynamic.NewForConfig(client.RestConfig)
		if err != nil {
			initErr = err
			return
		}

		// // disable klog
		klog.InitFlags(nil)
		if err := flag.Set("logtostderr", "false"); err != nil {
			initErr = err
			return
		}
		if err := flag.Set("alsologtostderr", "false"); err != nil {
			initErr = err
			return
		}
		flag.Parse()
	})

	return initErr
}

func GetClient() *KubernetesClient {
	if client == nil {
		if err := Init(); err != nil {
			return nil
		}
	}
	return client
}
