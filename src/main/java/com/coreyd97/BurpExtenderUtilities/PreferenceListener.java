package com.coreyd97.BurpExtenderUtilities;

public interface PreferenceListener {
    void onPreferenceSet(Object source, String settingName, Object newValue);
}
