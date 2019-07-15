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
    private String serializedValue;
    private HashMap<String, Object> preferences;
    private HashMap<String, Type> preferenceTypes;
    private HashMap<String, Object> preferenceDefaults;

    public ProjectSettingStore(Preferences preferenceController, IBurpExtenderCallbacks callbacks,
                               String extensionIdentifier) throws MalformedURLException, UnsupportedEncodingException {
        this.preferenceController = preferenceController;
        this.callbacks = callbacks;
        this.httpService = callbacks.getHelpers().buildHttpService("com.coreyd97.burpextenderutilities", 65535, true);
        String encodedExtensionIdentifier = URLEncoder.encode(extensionIdentifier, "UTF-8");
        this.requestBytes = callbacks.getHelpers().buildHttpRequest(
                new URL(httpService.getProtocol(), httpService.getHost(), httpService.getPort(), "/" + encodedExtensionIdentifier));
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

    private void loadSettingsFromJson(String json){
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

        this.serializedValue = json;
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
        loadSettingsFromJson(new String(message));
        //Parse the value and load the setting elements.
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
