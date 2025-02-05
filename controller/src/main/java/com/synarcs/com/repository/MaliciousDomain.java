package com.synarcs.com.repository;

import io.micrometer.common.lang.NonNull;
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
@NoArgsConstructor
public class MaliciousDomain {

    @Id
    private String SLD;

    @NonNull
    private String Fqdn;

    private boolean forcedUnblocked;

}
