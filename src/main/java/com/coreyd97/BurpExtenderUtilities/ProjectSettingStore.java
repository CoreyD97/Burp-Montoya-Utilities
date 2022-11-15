package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MarkedHttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import lombok.Getter;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

class ProjectSettingStore implements HttpRequestResponse {

    private final Preferences preferenceController;
    private final MontoyaApi montoya;
    private final HttpService httpService;
    private final HttpRequest httpRequest;
    private final String extensionIdentifier;

    @Getter
    private final URL storeUrl;
    private String serializedValue;
    private HashMap<String, Object> preferences;
    private HashMap<String, Type> preferenceTypes;
    private HashMap<String, Object> preferenceDefaults;

    public ProjectSettingStore(Preferences preferenceController, MontoyaApi montoya,
                               String extensionIdentifier) throws MalformedURLException, UnsupportedEncodingException {
        this.preferenceController = preferenceController;
        this.montoya = montoya;
        this.httpService = HttpService.httpService("PROJECT-EXTENSION-PREFERENCE-STORE-DO-NOT-DELETE", 65535, true);
        this.extensionIdentifier = URLEncoder.encode(extensionIdentifier, "UTF-8");
        this.storeUrl = new URL("https", httpService.host(), httpService.port(), "/" + this.extensionIdentifier);
        this.httpRequest = HttpRequest.httpRequest(httpService, Arrays.asList(String.format("GET /%s HTTP/1.1", this.extensionIdentifier)), "");
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
        List<HttpRequestResponse> existingItems = montoya.siteMap().requestResponses(node -> node.url().equalsIgnoreCase(this.httpRequest().url()));

        //If we have an existing item
        if(existingItems.size() > 0){
            //Pick the first one
            HttpRequestResponse existingSettings = existingItems.get(0);
            //If it has a response body (settings json)
            if(existingSettings.httpResponse() != null){
                //Load it into our current store item.
                loadSettingsFromJson(existingSettings.httpResponse().bodyAsString());
            }
        }
    }

    public void resetSetting(String settingName){
        Gson gson = this.preferenceController.getGsonProvider().getGson();
        Object defaultValue = this.preferenceDefaults.getOrDefault(settingName, null);
        String jsonDefaultValue = gson.toJson(defaultValue);
        Object newInstance = gson.fromJson(jsonDefaultValue, this.preferenceTypes.get(settingName));
        setSetting(settingName, newInstance);
    }

    public void saveToProject(){
        this.serializedValue = this.preferenceController.getGsonProvider().getGson().toJson(this.preferences);
        this.montoya.siteMap().add(this);
    }

    public Type getSettingType(String settingName) {
        return this.preferenceTypes.get(settingName);
    }

    @Override
    public HttpRequest httpRequest() {
        return this.httpRequest;
    }

    @Override
    public HttpResponse httpResponse() {
        return HttpResponse.httpResponse(Arrays.asList("HTTP 200 OK"), serializedValue == null ? "" : serializedValue);
    }

    @Override
    public Annotations messageAnnotations() {
        return Annotations.annotations();
    }

    @Override
    public HttpRequestResponse withMessageAnnotations(Annotations messageAnnotations) {
        return this;
    }

    @Override
    public MarkedHttpRequestResponse withMarkers(List<Range> requestMarkers, List<Range> responseMarkers) {
        return withNoMarkers();
    }

    @Override
    public MarkedHttpRequestResponse withRequestMarkers(List<Range> requestMarkers) {
        return withNoMarkers();
    }

    @Override
    public MarkedHttpRequestResponse withRequestMarkers(Range... requestMarkers) {
        return withNoMarkers();
    }

    @Override
    public MarkedHttpRequestResponse withResponseMarkers(List<Range> responseMarkers) {
        return withNoMarkers();
    }

    @Override
    public MarkedHttpRequestResponse withResponseMarkers(Range... responseMarkers) {
        return withNoMarkers();
    }

    @Override
    public MarkedHttpRequestResponse withNoMarkers() {
        return MarkedHttpRequestResponse.markedRequestResponse(httpRequest,httpResponse());
    }
}
