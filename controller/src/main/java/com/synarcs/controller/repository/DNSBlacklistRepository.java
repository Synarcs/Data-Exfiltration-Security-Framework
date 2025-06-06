/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package com.synarcs.controller.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DNSBlacklistRepository extends JpaRepository<MaliciousDomain, String> {
    
    List<MaliciousDomain> findBySLD(String domain);
}
