package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;

public class PersistedObject{
  public PersistedObject(
    MontoyaApi api,
    String name,
    Preferences.Visibility vis
  ){
    this(api, new DefaultGsonProvider(), name, null, vis);
  }

  public PersistedObject(
    MontoyaApi api,
    String name,
    Object defaultObject,
    Preferences.Visibility vis
  ){
    this(api, new DefaultGsonProvider(), name, defaultObject, vis);
  }

  public PersistedObject(
    MontoyaApi api, IGsonProvider gsonProvider,
    String name,
    Object defaultObject,
    Preferences.Visibility vis
  ){
    _PERSISTED_NAME = name;
    _prefs = new Preferences(api, gsonProvider);
    _prefs.register(name, this.getClass(), defaultObject, vis);
  }

  public void save(){ _prefs.set(_PERSISTED_NAME, this); }

  protected transient final String      _PERSISTED_NAME;
  protected transient final Preferences _prefs;

  //DO NOT USE!
  //disabled no-arg constructor
  private PersistedObject(){
    _PERSISTED_NAME = null;
    _prefs          = null;
  }
}