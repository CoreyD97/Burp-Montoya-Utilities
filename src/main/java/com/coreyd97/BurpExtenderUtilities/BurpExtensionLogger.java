package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;
public class BurpExtensionLogger implements ILogProvider {
    final MontoyaApi montoyaApi;

    public BurpExtensionLogger(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
    }

    @Override
    public void logOutput(String message) {
        montoyaApi.logging().logToOutput(message);
    }

    @Override
    public void logError(String errorMessage) {
        montoyaApi.logging().logToError(errorMessage);
    }
}
