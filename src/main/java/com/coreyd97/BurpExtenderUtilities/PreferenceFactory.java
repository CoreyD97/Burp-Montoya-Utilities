package com.coreyd97.BurpExtenderUtilities;

import burp.IBurpExtenderCallbacks;

public abstract class PreferenceFactory {

    protected Preferences prefs;
    protected IGsonProvider gsonProvider;
    protected ILogProvider logProvider;

    public PreferenceFactory(String extensionIdentifier, IGsonProvider gsonProvider,
                             ILogProvider logProvider, IBurpExtenderCallbacks callbacks){
        this.gsonProvider = gsonProvider;
        this.logProvider = logProvider;
        prefs = new Preferences(extensionIdentifier, gsonProvider, logProvider, callbacks);
    }

    public PreferenceFactory(String extensionIdentifier, IGsonProvider gsonProvider, IBurpExtenderCallbacks callbacks){
        this.gsonProvider = gsonProvider;
        prefs = new Preferences(extensionIdentifier, gsonProvider, callbacks);
    }

    protected abstract void createDefaults();

    protected abstract void registerTypeAdapters();

    protected abstract void registerSettings();

    public Preferences buildPreferences(){
        this.registerTypeAdapters();
        this.createDefaults();
        this.registerSettings();
        return this.prefs;
    }
}
