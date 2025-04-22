package model

import (
	"context"
	"os"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils/iowatchers"
	"github.com/fsnotify/fsnotify"
)

func WatchEvents(ctx context.Context, doneChan, globalNodeAgentFsWatchCloseChan chan bool,
	sockWatcher *fsnotify.Watcher) {
	for {
		select {
		case <-ctx.Done():
			doneChan <- true // close this watcher since the ctx from parent was cancelled and main goroutine is aware of close
			return
		case ev, cls := <-sockWatcher.Events:
			if !cls {
				utils.Log("Channel for fs notify event closed")
				doneChan <- true
				globalNodeAgentFsWatchCloseChan <- true // aware the root goroutine the channel has closed that error watching the path
				return
			}
			if ev.Has(fsnotify.Remove) {
				globalNodeAgentFsWatchCloseChan <- true // the agent should terminate itself considering the unix model inferencing path is required and not closed
			}
		case err := <-sockWatcher.Errors:
			doneChan <- true
			globalNodeAgentFsWatchCloseChan <- true
			utils.Log("Channel for fs notify event error ", err.Error())
			return
		}
	}
}

func OnnxModelFsUnixMountWatcher(ctx context.Context, globalNodeAgentFsWtchChan chan bool) {

	modelPaths := []string{
		utils.ONNX_INFERENCE_UNIX_SOCKET_EGRESS,
		utils.ONNX_INFERENCE_UNIX_SOCKET_INGRESS,
	}

	for _, path := range modelPaths {
		if _, err := os.Stat(path); err != nil {
			// there is no need to an inotify watcher over file path
			// 	 since the main node agent must error out considering the file path does not exist
			globalNodeAgentFsWtchChan <- true
			return
		}
	}
	doneChan := make(chan bool)
	sockWatcher, err := iowatchers.NewInotifySystemWatcher()
	if err != nil {
		globalNodeAgentFsWtchChan <- true
		return
	}
	go WatchEvents(ctx, doneChan, globalNodeAgentFsWtchChan, sockWatcher)

	for _, path := range modelPaths {
		utils.Log("Adding FSNotify Watcher for Fs.Remove events over path ", path)
		if err := sockWatcher.Add(path); err != nil {
			utils.Log("error adding watcher", path)
			globalNodeAgentFsWtchChan <- true
			doneChan <- true
		}
	}

	<-doneChan

}
