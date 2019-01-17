package com.coreyd97.BurpExtenderUtilities;

import burp.IBurpExtenderCallbacks;

import java.lang.reflect.Type;
import java.util.HashMap;

public class Preferences {

    private final IGsonProvider gsonProvider;
    private final IBurpExtenderCallbacks callbacks;
    private final HashMap<String, Object> settings;
    private final HashMap<String, Object> defaults;
    private final HashMap<String, Type> settingTypes;

    public Preferences(final IGsonProvider gsonProvider, final IBurpExtenderCallbacks callbacks){
        this.gsonProvider = gsonProvider;
        this.callbacks = callbacks;
        this.settings = new HashMap<>();
        this.defaults = new HashMap<>();
        this.settingTypes = new HashMap<>();
    }

    public void addSetting(String settingName, Type type){
        this.addSetting(settingName, type, null);
    }

    public <T> void addSetting(String settingName, Class<T> clazz){
        this.addSetting(settingName, clazz, null);
    }

    public void addSetting(String settingName, Type type, Object defaultValue){
        //Get setting from burp settings.
        Object storedValue = getBurpSetting(settingName, type);
        this.settingTypes.put(settingName, type);

        if(storedValue != null){
            this.settings.put(settingName, storedValue);
        }else{
            if(defaultValue != null){
                setSetting(settingName, defaultValue);
            }else{
                this.settings.put(settingName, null);
            }
        }

        this.defaults.put(settingName, defaultValue);
    }

    public <T> void addSetting(String settingName, Class<T> clazz, T defaultValue){
        //Get setting from burp settings.
        T storedValue = (T) getBurpSetting(settingName, clazz);
        this.settingTypes.put(settingName, clazz);

        if(storedValue != null){
            this.settings.put(settingName, storedValue);
        }else{
            if(defaultValue != null){
                setSetting(settingName, defaultValue);
            }else{
                this.settings.put(settingName, null);
            }
        }

        this.defaults.put(settingName, defaultValue);
    }


    private void storePreference(String settingName, String jsonValue){
        this.callbacks.saveExtensionSetting(settingName, jsonValue);
    }

    public void setSetting(String settingName, Object value) {
        Type type = this.settingTypes.get(settingName);
        String jsonValue = gsonProvider.getGson().toJson(value, type);
        storePreference(settingName, jsonValue);

        this.settings.put(settingName, value);
    }

    public void resetSetting(String settingName){
        setSetting(settingName, this.defaults.getOrDefault(settingName, null));
    }

    public Object getSetting(String settingName){
        return this.settings.get(settingName);
    }

    public Type getSettingType(String settingName) {
        return settingTypes.get(settingName);
    }

    private Object getBurpSetting(String settingName, Type settingType) {
        String storedValue = this.callbacks.loadExtensionSetting(settingName);
        if(storedValue == null) return null;

        return gsonProvider.getGson().fromJson(storedValue, settingType);
    }
}
