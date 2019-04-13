package com.coreyd97.BurpExtenderUtilities;

import burp.ICookie;

import java.util.Date;

public class FixCookie implements ICookie {

    private final ICookie originalCookie;
    private final String domain;

    public FixCookie(ICookie originalCookie, String domain){
        this.originalCookie = originalCookie;
        this.domain = domain;
    }


    @Override
    public String getDomain() {
        return
                originalCookie.getDomain() != null ? originalCookie.getDomain() : domain;
    }

    @Override
    public String getPath() {
        return originalCookie.getPath();
    }

    @Override
    public Date getExpiration() {
        return originalCookie.getExpiration();
    }

    @Override
    public String getName() {
        return originalCookie.getName();
    }

    @Override
    public String getValue() {
        return originalCookie.getValue();
    }
}
