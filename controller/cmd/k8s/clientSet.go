package k8s

import (
	"log"
	"os"
	"path/filepath"

	"github.com/Synarcs/DNSObelisk/controller/conf"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type K8sClientSet struct {
	ClientSet *kubernetes.Clientset
	Config    *rest.Config
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

	if conf.DEBUG {
		log.Println("Connected to clientset for dynamic network policy over remote c2 server Ip's", config.Host)
	}

	clientSet, err := kubernetes.NewForConfig(config)

	if err != nil {
		return nil, err
	}

	log.Println("Successfully loaded K8s client from kubeconfig path ", kubeconfig)
	return &K8sClientSet{
		ClientSet: clientSet,
		Config:    config,
	}, nil
}
