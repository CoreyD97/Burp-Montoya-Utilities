package com.coreyd97.BurpExtenderUtilities;

import burp.IBurpExtenderCallbacks;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

public class Preferences {

    private final IGsonProvider gsonProvider;
    private final IBurpExtenderCallbacks callbacks;
    private final HashMap<String, Object> settings;
    private final HashMap<String, Object> defaults;
    private final HashMap<String, Type> settingTypes;
    private final ArrayList<String> volatileKeys;
    private final ArrayList<SettingListener> settingListeners;

    public Preferences(final IGsonProvider gsonProvider, final IBurpExtenderCallbacks callbacks){
        this.gsonProvider = gsonProvider;
        this.callbacks = callbacks;
        this.settings = new HashMap<>();
        this.defaults = new HashMap<>();
        this.settingTypes = new HashMap<>();
        this.volatileKeys = new ArrayList<>();
        this.settingListeners = new ArrayList<>();
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
                setSetting(settingName, defaultValue, true);
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
                setSetting(settingName, defaultValue, true);
            }else{
                this.settings.put(settingName, null);
            }
        }

        this.defaults.put(settingName, defaultValue);
    }

    public void addVolatileSetting(String settingName, Type type){
        this.volatileKeys.add(settingName);
        this.addSetting(settingName, type);
    }

    public void addVolatileSetting(String settingName, Class clazz){
        this.volatileKeys.add(settingName);
        this.addSetting(settingName, clazz);
    }

    public void addVolatileSetting(String settingName, Type type, Object defaultValue){
        this.volatileKeys.add(settingName);
        this.addSetting(settingName, type, defaultValue);
    }

    public <T> void addVolatileSetting(String settingName, Class<T> clazz, T defaultValue){
        this.volatileKeys.add(settingName);
        this.addSetting(settingName, clazz, defaultValue);
    }


    private void storePreference(String settingName, String jsonValue){
        this.callbacks.saveExtensionSetting(settingName, jsonValue);
    }

    public void setSetting(String settingName, Object value){
        this.setSetting(settingName, value, true);
    }

    public void setSetting(String settingName, Object value, boolean notifyListeners) {
        Type type = this.settingTypes.get(settingName);
        Object oldValue = this.getSetting(settingName);
        if(value.equals(oldValue)) return;

        String jsonValue = gsonProvider.getGson().toJson(value, type);
        if(!volatileKeys.contains(settingName))
            storePreference(settingName, jsonValue);

        this.settings.put(settingName, value);

        if(!notifyListeners) return;
        for (SettingListener settingListener : this.settingListeners) {
            settingListener.onPreferenceSet(settingName, value);
        }
    }

    public void resetSetting(String settingName){
        setSetting(settingName, this.defaults.getOrDefault(settingName, null), true);
    }

    public void resetSettings(Set<String> keys){
        for (String key : keys) {
            resetSetting(key);
        }
    }

    public Set<String> getPreferenceKeys(){
        return this.settings.keySet();
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

        try {
            return gsonProvider.getGson().fromJson(storedValue, settingType);
        }catch (Exception e){
            callbacks.printError("Could not load stored setting \"" + storedValue + "\". This may be due to a change in stored types. Falling back to default.");
            return null;
        }
    }

    public void addSettingListener(SettingListener settingListener){
        this.settingListeners.add(settingListener);
    }

    public void removeSettingListener(SettingListener settingListener){
        this.settingListeners.remove(settingListener);
    }
}
