package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;

public abstract class PreferenceFactory {

    protected Preferences prefs;
    protected IGsonProvider gsonProvider;
    protected ILogProvider logProvider;

    public PreferenceFactory(MontoyaApi montoyaApi, IGsonProvider gsonProvider,
                             ILogProvider logProvider){
        this.gsonProvider = gsonProvider;
        this.logProvider = logProvider;
        prefs = new Preferences(montoyaApi, gsonProvider, logProvider);
    }

    public PreferenceFactory(MontoyaApi montoyaApi, IGsonProvider gsonProvider){
        this.gsonProvider = gsonProvider;
        prefs = new Preferences(montoyaApi, gsonProvider);
    }

    public PreferenceFactory(MontoyaApi montoyaApi){
        this.gsonProvider = new DefaultGsonProvider();
        prefs = new Preferences(montoyaApi, gsonProvider);
    }

    public PreferenceFactory(MontoyaApi montoyaApi, ILogProvider logProvider){
        this.gsonProvider = new DefaultGsonProvider();
        prefs = new Preferences(montoyaApi, gsonProvider, logProvider);
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
