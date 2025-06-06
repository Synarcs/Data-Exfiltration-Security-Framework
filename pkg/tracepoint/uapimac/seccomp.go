/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package uapimac

import (
	"fmt"

	seccomp "github.com/seccomp/libseccomp-golang"
)

func GetSyscallIds(procId uint32) (*[]seccomp.ScmpSyscall, error) {

	var syscallIds []seccomp.ScmpSyscall
	_, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, fmt.Errorf("failed to create seccomp filter: %w", err)
	}

	// fork syscall
	forkCall, err := seccomp.GetSyscallFromName("fork")
	if err != nil {
		return nil, fmt.Errorf("failed to get fork syscall: %w", err)
	}
	syscallIds = append(syscallIds, forkCall)

	vfork, err := seccomp.GetSyscallFromName("vfork")
	if err != nil {
		return nil, fmt.Errorf("failed to get vfork syscall: %w", err)
	}

	syscallIds = append(syscallIds, vfork)
	cloneCall, err := seccomp.GetSyscallFromName("clone")
	if err != nil {
		return nil, fmt.Errorf("failed to get clone syscall: %w", err)
	}

	syscallIds = append(syscallIds, cloneCall)
	return &syscallIds, nil
}

func NewFilter(procId uint32) (*seccomp.ScmpFilter, error) {
	filter, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, fmt.Errorf("failed to create seccomp filter: %w", err)
	}
	return filter, nil
}
