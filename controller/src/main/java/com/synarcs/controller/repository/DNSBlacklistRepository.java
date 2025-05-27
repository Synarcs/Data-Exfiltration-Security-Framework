/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package com.synarcs.controller.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DNSBlacklistRepository extends JpaRepository<MaliciousDomain, String> {
    
    List<MaliciousDomain> findBySLD(String domain);
}
