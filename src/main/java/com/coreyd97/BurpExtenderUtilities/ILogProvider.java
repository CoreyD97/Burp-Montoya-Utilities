package com.coreyd97.BurpExtenderUtilities;

public interface ILogProvider {
    void logOutput(String message);
    void logError(String errorMessage);
}
