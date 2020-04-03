package main

import (
	//"flag"
	"log"
	"os"
	"time"

	"github.com/s1061123/macvlan-networkpolicy/pkg/server"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"
)

const logFlushFreqFlagName = "log-flush-frequency"

var logFlushFreq = pflag.Duration(logFlushFreqFlagName, 5*time.Second, "Maximum number of seconds between log flushes")

// KlogWriter serves as a bridge between the standard log package and the glog package.
type KlogWriter struct{}

// Write implements the io.Writer interface.
func (writer KlogWriter) Write(data []byte) (n int, err error) {
	klog.InfoDepth(1, string(data))
	return len(data), nil
}

func initLogs() {
	log.SetOutput(KlogWriter{})
	log.SetFlags(0)
	go wait.Forever(klog.Flush, *logFlushFreq)
}

func main() {
	initLogs()
	defer klog.Flush()
	opts := server.NewOptions()

	cmd := &cobra.Command{
		Use:  "macvlan-networkpolicy-node",
		Long: `TBD`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := opts.Validate(args); err != nil {
				klog.Fatalf("failed validate: %v", err)
			}

			if err := opts.Run(); err != nil {
				klog.Exit(err)
			}
		},
	}
	opts.AddFlags(cmd.Flags())

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
