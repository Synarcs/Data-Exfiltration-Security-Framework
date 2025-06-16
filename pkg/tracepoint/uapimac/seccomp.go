/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package uapimac

import (
	"fmt"
	"syscall"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	seccomp "github.com/seccomp/libseccomp-golang"
)

func GetSyscallIds() (*[]seccomp.ScmpSyscall, error) {

	var syscallIds []seccomp.ScmpSyscall

	// fork syscall
	forkCall, err := seccomp.GetSyscallFromNameByArch("fork", utils.CpuArchPerSeccompProfile())
	if err != nil {
		return nil, fmt.Errorf("failed to get fork syscall: %w", err)
	}
	syscallIds = append(syscallIds, forkCall)

	vfork, err := seccomp.GetSyscallFromNameByArch("vfork", utils.CpuArchPerSeccompProfile())
	if err != nil {
		return nil, fmt.Errorf("failed to get vfork syscall: %w", err)
	}

	syscallIds = append(syscallIds, vfork)
	cloneCall, err := seccomp.GetSyscallFromNameByArch("clone", utils.CpuArchPerSeccompProfile())
	if err != nil {
		return nil, fmt.Errorf("failed to get clone syscall: %w", err)
	}
	syscallIds = append(syscallIds, cloneCall)

	udpv4_send, err := seccomp.GetSyscallFromNameByArch("sendmsg", utils.CpuArchPerSeccompProfile())
	if err != nil {
		return nil, fmt.Errorf("failed to get clone syscall: %w", err)
	}
	syscallIds = append(syscallIds, udpv4_send)

	return &syscallIds, nil
}

func NewFilter(procId uint32) (*seccomp.ScmpFilter, error) {
	filter, err := seccomp.NewFilter(seccomp.ActErrno.SetReturnCode(int16(syscall.EPERM)))
	if err != nil {
		return nil, fmt.Errorf("failed to create seccomp filter: %w", err)
	}

	syscallIds, err := GetSyscallIds()
	if err != nil {
		return nil, err
	}

	// TODO: create requrie strict deny for syscall tied to process in kernel
	for _, syscallIds := range *syscallIds {
		utils.Log("syscall id ", syscallIds)
	}

	if err := filter.Load(); err != nil {
		return nil, err
	}
	return filter, nil
}
