package server

import (
	"flag"
	"fmt"
	"strings"

	"github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/controllers"
	"github.com/spf13/pflag"

	"k8s.io/klog"
	utilnode "k8s.io/kubernetes/pkg/util/node"
)

// Options stores option for the command
type Options struct {
	// kubeconfig is the path to a KubeConfig file.
	Kubeconfig string
	// master is used to override the kubeconfig's URL to the apiserver
	master              string
	hostnameOverride    string
	hostPrefix          string
	containerRuntime    controllers.RuntimeKind
	containerRuntimeStr string
	networkPlugins      []string
	// errCh is the channel that errors will be sent
	errCh chan error
}

// AddFlags adds command line flags into command
func (o *Options) AddFlags(fs *pflag.FlagSet) {
	klog.InitFlags(nil)
	fs.SortFlags = false
	fs.StringVar(&o.containerRuntimeStr, "container-runtime", "crio", "Container runtime using for the cluster. Possible values: 'crio', 'docker'. ")
	fs.StringVar(&o.Kubeconfig, "kubeconfig", o.Kubeconfig, "Path to kubeconfig file with authorization information (the master location is set by the master flag).")
	fs.StringVar(&o.master, "master", o.master, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	fs.StringVar(&o.hostnameOverride, "hostname-override", o.hostnameOverride, "If non-empty, will use this string as identification instead of the actual hostname.")
	fs.StringVar(&o.hostPrefix, "host-prefix", o.hostnameOverride, "If non-empty, will use this string as prefix for host filesystem.")
	fs.StringSliceVar(&o.networkPlugins, "network-plugins", []string{"macvlan"}, "List of network plugins to be be considered for network policies.")
	fs.AddGoFlagSet(flag.CommandLine)
}

// Validate will check command line options
func (o *Options) Validate() error {

	// make it lower case
	containerRuntimeStr := strings.ToLower(o.containerRuntimeStr)
	if strings.Compare(containerRuntimeStr, "docker") == 0 {
		o.containerRuntime = controllers.Docker
	} else if strings.Compare(containerRuntimeStr, "crio") == 0 {
		o.containerRuntime = controllers.Crio
	} else {
		return fmt.Errorf("Invalid container-runtime option %s (possible value: \"docker\", \"crio\"", o.containerRuntimeStr)
	}
	return nil
}

// Run invokes server
func (o *Options) Run() error {
	defer close(o.errCh)

	server, err := NewServer(o)
	if err != nil {
		return err
	}

	hostname, err := utilnode.GetHostname(o.hostnameOverride)
	if err != nil {
		return err
	}
	klog.Infof("hostname: %v", hostname)

	go func() {
		err := server.Run(hostname)
		o.errCh <- err
	}()

	for {
		err := <-o.errCh
		if err != nil {
			return err
		}
	}
}

// NewOptions initializes Options
func NewOptions() *Options {
	return &Options{
		errCh: make(chan error),
	}
}
