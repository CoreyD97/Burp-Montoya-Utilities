package com.coreyd97.BurpExtenderUtilities;

import burp.IBurpExtenderCallbacks;

public class BurpExtensionLogger implements ILogProvider {

    IBurpExtenderCallbacks callbacks;

    public BurpExtensionLogger(IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
    }

    @Override
    public void logOutput(String message) {
        callbacks.printOutput(message);
    }

    @Override
    public void logError(String errorMessage) {
        callbacks.printError(errorMessage);
    }
}
