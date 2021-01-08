package com.coreyd97.BurpExtenderUtilities;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;

class ProjectSettingStore implements IHttpRequestResponse {

    private final Preferences preferenceController;
    private final IBurpExtenderCallbacks callbacks;
    private final IHttpService httpService;
    private final byte[] requestBytes;
    private final String extensionIdentifier;
    private String serializedValue;
    private HashMap<String, Object> preferences;
    private HashMap<String, Type> preferenceTypes;
    private HashMap<String, Object> preferenceDefaults;

    public ProjectSettingStore(Preferences preferenceController, IBurpExtenderCallbacks callbacks,
                               String extensionIdentifier) throws MalformedURLException, UnsupportedEncodingException {
        this.preferenceController = preferenceController;
        this.callbacks = callbacks;
        this.httpService = callbacks.getHelpers().buildHttpService("PROJECT-EXTENSION-PREFERENCE-STORE-DO-NOT-DELETE", 65535, true);
        this.extensionIdentifier = URLEncoder.encode(extensionIdentifier, "UTF-8");
        this.requestBytes = callbacks.getHelpers().buildHttpRequest(
                new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), "/" + this.extensionIdentifier));
        this.preferences = new HashMap<>();
        this.preferenceTypes = new HashMap<>();
        this.preferenceDefaults = new HashMap<>();
    }

    public ProjectSettingStore(Preferences preferenceController, IBurpExtenderCallbacks callbacks,
                               String domain, String extensionIdentifier) throws MalformedURLException, UnsupportedEncodingException {
        this.preferenceController = preferenceController;
        this.callbacks = callbacks;
        this.httpService = callbacks.getHelpers().buildHttpService(domain, 65535, true);
        this.extensionIdentifier = URLEncoder.encode(extensionIdentifier, "UTF-8");
        this.requestBytes = callbacks.getHelpers().buildHttpRequest(
                new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), "/" + this.extensionIdentifier));
        this.preferences = new HashMap<>();
        this.preferenceTypes = new HashMap<>();
        this.preferenceDefaults = new HashMap<>();
    }


    public void registerSetting(String settingName, Type type) {
        this.registerSetting(settingName, type, null);
    }

    public void registerSetting(String settingName, Type type, Object defaultValue) {
        if(this.preferenceTypes.containsKey(settingName)){
            throw new RuntimeException("Setting " + settingName + " has already been registered in the project settings store!");
        }

        this.preferenceTypes.put(settingName, type);

        if(this.preferences.get(settingName) == null){
            this.preferences.put(settingName, defaultValue);
        }else{
            try {
                String existingSerializedValue = (String) this.preferences.get(settingName);
                Object deserializedValue = this.preferenceController.getGsonProvider()
                        .getGson().fromJson(existingSerializedValue, type);
                this.preferences.put(settingName, deserializedValue);
                preferenceController.logOutput("Deserialized existing value.");
            } catch (Exception e) {
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                preferenceController.logError(sw.toString());
                preferenceController.logError("Could not deserialize the loaded value for setting " +
                        "\"" + settingName + "\" to type \"" + type + "\". Falling back to the default value.");
                this.preferences.put(settingName, defaultValue);
            }
        }

        this.preferenceDefaults.put(settingName, defaultValue);
        preferenceController.logOutput("Project setting \"" + settingName + "\" registered with type " + type.getTypeName()
                + " and default value: " + (defaultValue != null ? defaultValue : "null"));
    }

    void setSetting(String setting, Object value){
        this.preferences.put(setting, value);
        saveToProject();
    }

    Object getSetting(String settingName){
        return this.preferences.get(settingName);
    }

    void loadSettingsFromJson(String json){
        //Initially load the stored values as key, serialized value pairs.
        //When settings are registered, we will get their value and convert into the requested type.
        //We can then update the entry with the converted type.
        Gson gson = this.preferenceController.getGsonProvider().getGson();
        HashMap<String, String> tempPreferences = gson.fromJson(json, new TypeToken<HashMap<String, Object>>(){}.getType());
        if(this.preferences == null){
            this.preferences = new HashMap<>();
        }
        if(tempPreferences != null) {
            for (String key : tempPreferences.keySet()) {
                Object value = tempPreferences.get(key);
                this.preferences.put(key, gson.toJson(value));
            }
        }

        if(this.serializedValue != null){
            //If we already have a serialized value, overwrite its entries with any from the new one to combine them
            HashMap<String, String> currentJson = gson.fromJson(serializedValue, new TypeToken<HashMap<String, String>>(){}.getType());
            currentJson.putAll(tempPreferences);
            json = gson.toJson(currentJson);
        }
        this.serializedValue = json;
    }

    void loadFromSiteMap(){
        //Load existing from sitemap
        IHttpRequestResponse[] existingItems = callbacks.getSiteMap(
                this.httpService.toString() + "/" + extensionIdentifier);

        //If we have an existing item
        if(existingItems.length != 0){
            //Pick the first one
            IHttpRequestResponse existingSettings = existingItems[0];
            //If it has a response body (settings json)
            if(existingSettings.getResponse() != null){
                //Load it into our current store item.
                loadSettingsFromJson(new String(existingSettings.getResponse()));
            }
        }
    }

    public void saveToProject(){
        this.serializedValue = this.preferenceController.getGsonProvider().getGson().toJson(this.preferences);
        this.callbacks.addToSiteMap(this);
    }

    @Override
    public byte[] getRequest() {
        return this.requestBytes;
    }

    @Override
    public void setRequest(byte[] message) {}

    @Override
    public byte[] getResponse() {
        if(serializedValue == null) return "".getBytes();
        return serializedValue.getBytes();
    }

    @Override
    public void setResponse(byte[] message) {
        if(message == null){
            this.serializedValue = null;
        }else {
            //Parse the value and load the setting elements.
            loadSettingsFromJson(new String(message));
        }
    }

    @Override
    public String getComment() {
        return null;
    }

    @Override
    public void setComment(String comment) {}

    @Override
    public String getHighlight() {
        return null;
    }

    @Override
    public void setHighlight(String color) {}

    @Override
    public IHttpService getHttpService() {
        return this.httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {}

    public Type getSettingType(String settingName) {
        return this.preferenceTypes.get(settingName);
    }
}
