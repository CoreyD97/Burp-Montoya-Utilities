package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;

public abstract class PreferenceFactory {

    protected Preferences prefs;
    protected IGsonProvider gsonProvider;
    protected ILogProvider logProvider;

    public PreferenceFactory(final MontoyaApi montoyaApi){
        this.gsonProvider = new DefaultGsonProvider();
        prefs = new Preferences(montoyaApi, gsonProvider);
    }

    public PreferenceFactory(final MontoyaApi montoyaApi, final IGsonProvider gsonProvider){
        this.gsonProvider = gsonProvider;
        prefs = new Preferences(montoyaApi, gsonProvider);
    }

    public PreferenceFactory(final MontoyaApi montoyaApi, final ILogProvider logProvider){
        this.gsonProvider = new DefaultGsonProvider();
        this.logProvider  = logProvider;
        prefs = new Preferences(montoyaApi, gsonProvider, logProvider);
    }

    public PreferenceFactory(final MontoyaApi montoyaApi, final IGsonProvider gsonProvider,
                             final ILogProvider logProvider){
        this.gsonProvider = gsonProvider;
        this.logProvider = logProvider;
        prefs = new Preferences(montoyaApi, gsonProvider, logProvider);
    }

    public PreferenceFactory(final MontoyaApi montoyaApi, final String namespace){
        this.gsonProvider = new DefaultGsonProvider();
        prefs = new Preferences(montoyaApi, gsonProvider, namespace);
    }

    public PreferenceFactory(final MontoyaApi montoyaApi, final IGsonProvider gsonProvider, final String namespace){
        this.gsonProvider = gsonProvider;
        prefs = new Preferences(montoyaApi, gsonProvider, namespace);
    }

    public PreferenceFactory(final MontoyaApi montoyaApi, final ILogProvider logProvider, final String namespace){
        this.gsonProvider = new DefaultGsonProvider();
        this.logProvider  = logProvider;
        prefs = new Preferences(montoyaApi, gsonProvider, logProvider, namespace);
    }

    public PreferenceFactory(final MontoyaApi montoyaApi, final IGsonProvider gsonProvider,
                             final ILogProvider logProvider, final String namespace){
        this.gsonProvider = gsonProvider;
        this.logProvider  = logProvider;
        prefs = new Preferences(montoyaApi, gsonProvider, logProvider, namespace);
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
