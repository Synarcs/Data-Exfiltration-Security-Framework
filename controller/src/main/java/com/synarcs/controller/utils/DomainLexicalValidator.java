package com.synarcs.controller.utils;

import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class DomainLexicalValidator {

    // Note the data plane eBPF node agent at endpoint will removed the fqdn dilimeter at end when streaming to topic consumed by controller eg (apple.com, not apple.com.)
    // all the validation follows DNS RFC 1035

    public String[] getLabels(String domain) {
        return domain.split(".");
    }

    public boolean validateSld(String sld) {

        String[] labels = getLabels(sld);
        if (labels.length != 2) return false;

        for (String label: labels) {
            if (label.length() > 63) {
                return false;
            }
        }

        return true;
    }

    public boolean validateTld(String tld) {
        String[] labels = getLabels(tld);
        return labels.length == 1 && labels[0].length() <= 63;
    }

    public boolean validDomain(String domain) {
        String[] labels = getLabels(domain);
        
        if (labels.length > 127) return false;

        for (String label: labels){
            if (label.length() > 63) {
                return false;
            }
        }

        return true;
    }
}
