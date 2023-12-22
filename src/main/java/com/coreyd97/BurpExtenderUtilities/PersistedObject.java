package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;

import java.lang.reflect.Type;

public abstract class PersistedObject{
  public PersistedObject(
    MontoyaApi api,
    String name,
    Preferences.Visibility vis
  ){
    this(api, name, null, vis);
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
    _api = api;
    _gsonProvider = gsonProvider;
    _PERSISTED_NAME = name;
    _vis = vis;

    _prefs = new Preferences(_api, _gsonProvider);
  }

  public void save(){ _prefs.set(_PERSISTED_NAME, this); }

  /////////////////////
  // PREFERENCES API //
  /////////////////////
  public void reset(){
    _prefs.reset(_PERSISTED_NAME);
  }

  protected transient final String      _PERSISTED_NAME;
  protected transient final Preferences _prefs;

  protected void register(){
    this.register(this.getClass(), this);
  }

  protected void register(Type persistedType, Object defaultValue){
    _prefs.register(_PERSISTED_NAME, persistedType, defaultValue, _vis);
  }

  private final transient MontoyaApi             _api;
  private final transient IGsonProvider          _gsonProvider;
  private final transient Preferences.Visibility _vis;

  //DO NOT USE!
  //disabled no-arg constructor
  private PersistedObject(MontoyaApi api){
    _PERSISTED_NAME = null;
    _prefs          = null;
    _api            = null;
    _gsonProvider   = null;
    _vis            = null;
  }
}