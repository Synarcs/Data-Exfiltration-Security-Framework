package com.synarcs.com.powerdns;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RecursorBlackList<T> implements Serializable{

    /*
     *  The controller send  this to dynamically blacklist the domains which are not first blacklisted to powerdns 
     *  The powerdns recursor blacklist over it using the presolve hooks used by pdns recursosr internally while using libpcap for processing dns queries as forwarder to local or external zones 
     */
    private Set<T> domains = new HashSet<>();
    private Logger log = LoggerFactory.getLogger(RecursorBlackList.class);

    public RecursorBlackList() {
        super();
    }

    public Set<T> getAllRecursorBlackListDomains() {
        return domains;
    }

    public void sddmaliciousDomainToRecursorBlackList(T domain) {
        this.domains.add(domain);
    }

    public void blacklistDomain(T domain) {
        log.info("call the powerdns recrusor to balcklist this domain");
        this.getAllRecursorBlackListDomains();
    }

    @Override
    public String toString() {
        return this.domains.toString();
    }
}
