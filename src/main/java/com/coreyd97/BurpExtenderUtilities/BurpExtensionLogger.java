package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class BurpExtensionLogger implements ILogProvider {
    final MontoyaApi montoyaApi;

    @Override
    public void logOutput(String message) {
        montoyaApi.logging().logToOutput(message);
    }

    @Override
    public void logError(String errorMessage) {
        montoyaApi.logging().logToError(errorMessage);
    }
}
