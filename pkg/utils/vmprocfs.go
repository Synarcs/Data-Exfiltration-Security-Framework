package utils

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// the same can be returned from kernel using bpf_get_curr_comm() task_struct, and bpf_get_current_pid_tgid, bpf_get_current_pid_ugid
// since running in user space use the kernel mounted process file system
type ProcessInfo struct {
	Pid       string
	PPid      string
	ThreadId  string
	GroupId   string
	Command   string
	ProcComm  string
	OpenFiles []string
	UserOwner string
}

func IsValidProcVfsMounted(procId int) (bool, error) {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", procId)); err != nil {
		return false, err
	}

	return true, nil
}

// Get the process infor from the kernel proces vfs
func GetProcessInfo(pid int) (*ProcessInfo, error) {
	if _, err := IsValidProcVfsMounted(pid); err != nil {
		return nil, err
	}

	procInfo := &ProcessInfo{}
	procInfo.Pid = strconv.Itoa(pid)
	processDir := filepath.Join("/proc", strconv.Itoa(pid))
	cmdlineBytes, err := os.ReadFile(filepath.Join(processDir, "cmdline"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	command := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
	procInfo.Command = command

	exeLink, err := os.Readlink(filepath.Join(processDir, "exe"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	procInfo.ProcComm = exeLink

	childdirFd, _ := os.ReadDir(filepath.Join(processDir, "fd"))
	var openFiles []string = make([]string, 0)
	for _, fdDirLink := range childdirFd {
		if fdLink, err := os.Readlink(filepath.Join(processDir, "fd", fdDirLink.Name())); err != nil {
			continue
		} else {
			openFiles = append(openFiles, fdLink)
		}
	}
	procInfo.OpenFiles = openFiles

	procStatus := filepath.Join(processDir, "status")
	if _, err := os.Stat(procStatus); err != nil {
		return nil, err
	}

	file, _ := os.Open(procStatus)
	line := bufio.NewScanner(file)

	for line.Scan() {
		info := line.Text()
		if strings.HasPrefix(info, "Tgid") {
			procInfo.ThreadId = strings.Split(info, ":")[0]
		} else if strings.HasPrefix(info, "Uid") {
			cleanStr := strings.TrimSpace(strings.Split(info, ":")[1])
			uid := strings.Fields(cleanStr)
			if len(uid) > 0 {
				userinfo, err := user.LookupId(uid[0])
				if err != nil {
					log.Printf("Error Looking up user Info for user %s", uid[:])
				}
				procInfo.UserOwner = userinfo.Username
				procInfo.GroupId = userinfo.Gid
			}
		} else if strings.HasPrefix(info, "PPid") {
			procInfo.PPid = strings.Split(info, ":")[0]
		}
	}
	fmt.Println(procInfo)

	return procInfo, nil
}
