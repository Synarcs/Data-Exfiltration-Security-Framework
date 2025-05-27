/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package iowatchers

import (
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/fsnotify/fsnotify"
)

// Internally relies on kernel watchdog for fd emit over kqueue or async io to blocked poll socket
// save from unwanted jargon continuous poll syscall for stats for wasting cpu cycles
// rely on inotify and epoll for async io emit rather than polling
func NewInotifySystemWatcher() (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()

	if err != nil {
		utils.Log("error opening file watcher in kernel")
		return nil, err
	}

	return watcher, nil
}
