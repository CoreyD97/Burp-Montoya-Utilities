package com.coreyd97.BurpExtenderUtilities;

public interface SettingListener {
    void onPreferenceSet(String settingName, Object newValue);
}
