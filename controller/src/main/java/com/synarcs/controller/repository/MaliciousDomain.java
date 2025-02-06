package com.synarcs.controller.repository;

import jakarta.annotation.Nonnull;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@AllArgsConstructor
public class MaliciousDomain {

    @Id
    private String SLD;

    @Nonnull
    private String Fqdn;

    private boolean forcedUnblocked;

    public MaliciousDomain() {

    }
}
