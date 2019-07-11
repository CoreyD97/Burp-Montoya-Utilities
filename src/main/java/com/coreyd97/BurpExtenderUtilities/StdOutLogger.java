package com.coreyd97.BurpExtenderUtilities;

public class StdOutLogger implements ILogProvider {

    @Override
    public void logOutput(String message) {
        System.out.println(message);
    }

    @Override
    public void logError(String errorMessage) {
        System.err.println(errorMessage);
    }
}
