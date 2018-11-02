package com.coreyd97.BurpExtenderBase;

import burp.IBurpExtenderCallbacks;

import java.util.HashMap;

public class Preferences {

    private final IGsonProvider gsonProvider;
    private IBurpExtenderCallbacks callbacks;
    private HashMap<String, Object> settings;
    private HashMap<String, Class> settingClasses;

    public Preferences(final IGsonProvider gsonProvider, final IBurpExtenderCallbacks callbacks){
        this.gsonProvider = gsonProvider;
        this.callbacks = callbacks;
        this.settings = new HashMap<>();
        this.settingClasses = new HashMap<>();
    }

    public void addSetting(String settingName, Class clazz){
        this.addSetting(settingName, clazz, null);
    }

    public <T> void addSetting(String settingName, Class<T> clazz, T defaultValue){
        //Get setting from burp settings.
        T storedValue = (T) getBurpSetting(settingName, clazz);

        if(storedValue != null){
            this.settings.put(settingName, storedValue);
        }else{
            if(defaultValue != null){
                this.settings.put(settingName, defaultValue);
                storePreference(settingName, defaultValue);
            }else{
                this.settings.put(settingName, null);
            }
        }

        this.settingClasses.put(settingName, clazz);
    }

    private void storePreference(String settingName, Object value){
        this.callbacks.saveExtensionSetting(settingName, this.gsonProvider.getGson().toJson(value));
    }

    public void setSetting(String settingName, Object value) throws IllegalArgumentException {
        if(!this.settingClasses.get(settingName).isInstance(value)){
            throw new IllegalArgumentException("The specified value is not of type "
                    + this.settingClasses.get(settingName).getSimpleName());
        }

        this.settings.put(settingName, value);
        storePreference(settingName, value);
    }

    public Object getSetting(String settingName){
        return this.settings.get(settingName);
    }

    public Class getSettingClass(String settingName) {
        return settingClasses.get(settingName);
    }

    private <T> T getBurpSetting(String settingName, Class<T> settingClass) {
        String storedValue = this.callbacks.loadExtensionSetting(settingName);
        if(storedValue == null) return null;

        return gsonProvider.getGson().fromJson(storedValue, settingClass);
    }
}
