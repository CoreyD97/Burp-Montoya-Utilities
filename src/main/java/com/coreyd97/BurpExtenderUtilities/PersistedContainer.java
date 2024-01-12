package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;

public abstract class PersistedContainer{
  public PersistedContainer(MontoyaApi api, String name){
    this(api, new DefaultGsonProvider(), name);
  }

  public PersistedContainer(MontoyaApi api, IGsonProvider gsonProvider, String name){
    _PERSISTED_NAME = name;
    _prefs = new Preferences(api, gsonProvider);
  }

  public void save(){ _prefs.set(_PERSISTED_NAME, this); }

  public void unregister(){ _prefs.unregister(_PERSISTED_NAME); }

  public void reregister(){ _prefs.reregister(_PERSISTED_NAME); }

  protected transient final String      _PERSISTED_NAME;
  protected transient final Preferences _prefs;
}
