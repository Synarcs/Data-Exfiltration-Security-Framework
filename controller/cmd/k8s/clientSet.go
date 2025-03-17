package k8s

import (
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type K8sClientSet struct {
	ClientSet *kubernetes.Clientset
}

func InitK8sClientSet(configPath string) (*K8sClientSet, error) {

	var kubeconfig string

	if configPath == "" {
		if home, err := os.UserHomeDir(); err != nil {
			return nil, err
		} else {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	} else {
		kubeconfig = configPath
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	clientSet, err := kubernetes.NewForConfig(config)

	if err != nil {
		return nil, err
	}

	return &K8sClientSet{
		ClientSet: clientSet,
	}, nil
}
