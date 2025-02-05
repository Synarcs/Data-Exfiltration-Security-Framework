package com.synarcs.com.repository;

import org.springframework.context.annotation.Primary;

import io.micrometer.common.lang.NonNull;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
public class MaliciousDomain {

    @Id
    private String SLD;

    @NonNull
    private String Fqdn;

    private boolean forcedUnblocked;

    public MaliciousDomain() {

    }
}
