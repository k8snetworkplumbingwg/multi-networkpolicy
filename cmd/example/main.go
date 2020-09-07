package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/golang/glog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"

	clientset "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/clientset/versioned"
)

var (
	kuberconfig = flag.String("kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	master      = flag.String("master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
)

func main() {
	flag.Parse()

	cfg, err := clientcmd.BuildConfigFromFlags(*master, *kuberconfig)
	if err != nil {
		glog.Fatalf("Error building kubeconfig: %v", err)
	}

	exampleClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		glog.Fatalf("Error building example clientset: %v", err)
	}

	list, err := exampleClient.K8sCniCncfIoV1beta1().MultiNetworkPolicies("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		glog.Fatalf("Error listing all network attachment definitions: %v", err)
	}

	for _, nad := range list.Items {
		fmt.Printf("MultiNetworkPolicy %s\n", nad.Name)
	}
}
