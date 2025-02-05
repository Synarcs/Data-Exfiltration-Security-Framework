package com.synarcs.com.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface DNSBlacklistRepository extends JpaRepository<MaliciousDomain, String> {
    
    List<MaliciousDomain> findBySLD(String domain);
}
