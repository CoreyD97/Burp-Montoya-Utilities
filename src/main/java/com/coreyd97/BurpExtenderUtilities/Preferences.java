package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.coreyd97.BurpExtenderUtilities.TypeAdapter.AtomicIntegerTypeAdapter;
import com.coreyd97.BurpExtenderUtilities.TypeAdapter.ByteArrayToBase64TypeAdapter;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

public class Preferences {

    public enum Visibility {GLOBAL, PROJECT, VOLATILE}

    private ILogProvider logProvider;
    private final IGsonProvider gsonProvider;
    private final MontoyaApi montoya;
    private final HashMap<String, Object> preferences;
    private final HashMap<String, Object> preferenceDefaults;
    private final HashMap<String, Type> preferenceTypes;
    private final HashMap<String, Visibility> preferenceVisibilities;
    private final ArrayList<PreferenceListener> preferenceListeners;

    public Preferences(final MontoyaApi montoyaApi, final IGsonProvider gsonProvider, final ILogProvider logProvider){
        this(montoyaApi, gsonProvider);
        this.logProvider = logProvider;
    }

    public Preferences(final MontoyaApi montoyaApi, final IGsonProvider gsonProvider){
        this.montoya = montoyaApi;
        this.gsonProvider = gsonProvider;
        this.preferenceDefaults = new HashMap<>();
        this.preferences = new HashMap<>();
        this.preferenceTypes = new HashMap<>();
        this.preferenceVisibilities = new HashMap<>();
        this.preferenceListeners = new ArrayList<>();
        registerRequiredTypeAdapters();
    }

    private void registerRequiredTypeAdapters(){
        this.gsonProvider.registerTypeAdapter(AtomicInteger.class, new AtomicIntegerTypeAdapter());
        this.gsonProvider.registerTypeAdapter(byte[].class, new ByteArrayToBase64TypeAdapter());
    }

    public void registerSetting(String settingName, Type type){
        registerSetting(settingName, type, null, Visibility.GLOBAL);
    }

    public void registerSetting(String settingName, Type type, Object defaultValue){
        registerSetting(settingName, type, defaultValue, Visibility.GLOBAL);
    }

    public void registerSetting(String settingName, Type type, Visibility visibility){
        registerSetting(settingName, type, null, visibility);
    }

    public void registerSetting(String settingName, Type type, Object defaultValue, Visibility visibility){
        throwExceptionIfAlreadyRegistered(settingName);
        this.preferenceVisibilities.put(settingName, visibility);
        this.preferenceTypes.put(settingName, type);
        this.preferenceDefaults.put(settingName, defaultValue);

        Object previousValue;
        switch(visibility){
            case PROJECT -> previousValue = getProjectSettingFromBurp(settingName, type);
            case GLOBAL -> previousValue = getGlobalSettingFromBurp(settingName, type);
            default -> previousValue = defaultValue;
        }

        if(previousValue != null){
            this.preferences.put(settingName, previousValue);
        }else{
            this.preferences.put(settingName, defaultValue);
        }

        logOutput(String.format("Registered setting: [Key=%s, Scope=%s, Type=%s, Default=%s, Value=%s]",
                settingName, visibility, type, defaultValue, this.preferences.get(settingName)));

    }

    @Deprecated
    public void registerGlobalSetting(String settingName, Type type){
        registerSetting(settingName, type, Visibility.GLOBAL);
    }

    @Deprecated
    public void registerGlobalSetting(String settingName, Type type, Object defaultValue){
        registerSetting(settingName, type, defaultValue, Visibility.GLOBAL);
    }

    @Deprecated
    public void registerProjectSetting(String settingName, Type type) {
        registerSetting(settingName, type, Visibility.PROJECT);
    }

    @Deprecated
    public void registerProjectSetting(String settingName, Type type, Object defaultValue) {
        registerSetting(settingName, type, defaultValue, Visibility.PROJECT);
    }


    @Deprecated
    public void registerVolatileSetting(String settingName, Type type){
        registerSetting(settingName, type, Visibility.VOLATILE);
    }

    @Deprecated
    public void registerVolatileSetting(String settingName, Type type, Object defaultValue){
        registerSetting(settingName, type, defaultValue, Visibility.VOLATILE);
    }

    private void setGlobalSetting(String settingName, Object value) {
        Type type = this.preferenceTypes.get(settingName);
        Object currentValue = this.preferences.get(settingName);
        String currentValueJson = gsonProvider.getGson().toJson(currentValue, type);
        String newValueJson = gsonProvider.getGson().toJson(value, type);
        //Temporarily removed. Not saving preferences for instance variables.
//        if(newValueJson != null && newValueJson.equals(currentValueJson)) return;

        this.montoya.persistence().preferences().setString(settingName, newValueJson);
        this.preferences.put(settingName, value);
    }

    private void setProjectSetting(String settingName, Object value) {
        Type type = this.preferenceTypes.get(settingName);
        Object currentValue = this.preferences.get(settingName);
        String currentValueJson = gsonProvider.getGson().toJson(currentValue, type);
        String newValueJson = gsonProvider.getGson().toJson(value, type);
        //Temporarily removed. Not saving preferences for instance variables.
//        if(newValueJson != null && newValueJson.equals(currentValueJson)) return;
        this.montoya.persistence().extensionData().setString(settingName, newValueJson);
        this.preferences.put(settingName, value);
    }

    private Object getGlobalSettingFromBurp(String settingName, Type settingType) {
        String storedValue = getGlobalSettingJson(settingName);
        if(storedValue == null) return null;

//        logOutput(String.format("Value %s loaded for global setting \"%s\". Trying to deserialize.", storedValue, settingName));
        try {
            return gsonProvider.getGson().fromJson(storedValue, settingType);
        }catch (Exception e){
            logError("Could not load stored setting \"" + settingName
                    + "\". This may be due to a change in stored types. Falling back to default.");
            return null;
        }
    }

    private Object getProjectSettingFromBurp(String settingName, Type settingType) {
        String storedValue = getProjectSettingJson(settingName);
        if(storedValue == null) return null;

        try {
            return gsonProvider.getGson().fromJson(storedValue, settingType);
        }catch (Exception e){
            logError("Could not load stored setting \"" + settingName
                    + "\". This may be due to a change in stored types. Falling back to default.");
            return null;
        }
    }

    public HashMap<String, Visibility> getRegisteredSettings(){
        return this.preferenceVisibilities;
    }

    public <T> T getSetting(String settingName){
        Visibility visibility = this.preferenceVisibilities.get(settingName);
        if(visibility == null) throw new RuntimeException("Setting " + settingName + " has not been registered!");

        Object value = this.preferences.get(settingName);

        return (T) value;
    }

    public void setSetting(String settingName, Object value){
        setSetting(settingName, value, this);
    }

    public void setSetting(String settingName, Object value, Object eventSource){
        Visibility visibility = this.preferenceVisibilities.get(settingName);
        if(visibility == null) throw new RuntimeException("Setting " + settingName + " has not been registered!");
        switch (visibility) {
            case VOLATILE: {
                this.preferences.put(settingName, value);
                break;
            }
            case PROJECT: {
                this.setProjectSetting(settingName, value);
                break;
            }
            case GLOBAL: {
                this.setGlobalSetting(settingName, value);
                break;
            }
        }

        for (PreferenceListener preferenceListener : this.preferenceListeners) {
            preferenceListener.onPreferenceSet(eventSource, settingName, value);
        }
    }

    public Type getSettingType(String settingName) {
        Visibility visibility = this.preferenceVisibilities.get(settingName);
        if(visibility == null) throw new RuntimeException("Setting " + settingName + " has not been registered!");

        return this.preferenceTypes.get(settingName);
    }

    private String getGlobalSettingJson(String settingName) {
        return this.montoya.persistence().preferences().getString(settingName);
    }

    private String getProjectSettingJson(String settingName) {
        return this.montoya.persistence().extensionData().getString(settingName);
    }

    public void addSettingListener(PreferenceListener preferenceListener){
        this.preferenceListeners.add(preferenceListener);
    }

    public void removeSettingListener(PreferenceListener preferenceListener){
        this.preferenceListeners.remove(preferenceListener);
    }

    public void resetSetting(String settingName){
        Visibility visibility = this.preferenceVisibilities.get(settingName);
        if(visibility == null) throw new RuntimeException("Setting " + settingName + " has not been registered!");

        Object defaultValue = this.preferenceDefaults.getOrDefault(settingName, null);
        String jsonDefaultValue = gsonProvider.getGson().toJson(defaultValue);
        Object newInstance = gsonProvider.getGson().fromJson(jsonDefaultValue, this.preferenceTypes.get(settingName));

        this.setSetting(settingName, newInstance);

        for (PreferenceListener preferenceListener : this.preferenceListeners) {
            preferenceListener.onPreferenceSet(this, settingName, getSetting(settingName));
        }
    }

    public void resetSettings(Set<String> keys){
        for (String key : keys) {
            resetSetting(key);
        }
    }
    
    public void resetAllSettings(){
        HashMap<String, Preferences.Visibility> registeredSettings = getRegisteredSettings();
        resetSettings(registeredSettings.keySet());
    }

    IGsonProvider getGsonProvider() {
        return gsonProvider;
    }

    void logOutput(String message){
        if(this.logProvider != null)
            logProvider.logOutput(message);
    }

    void logError(String errorMessage){
        if(this.logProvider != null)
            logProvider.logError(errorMessage);
    }

    private void throwExceptionIfAlreadyRegistered(String settingName){
        if(this.preferenceVisibilities.get(settingName) != null)
            throw new RuntimeException("Setting " + settingName + " has already been registered with " +
                    this.preferenceVisibilities.get(settingName) + " visibility.");
    }
}
