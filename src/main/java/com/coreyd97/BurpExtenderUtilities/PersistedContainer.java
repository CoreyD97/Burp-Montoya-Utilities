package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;

public abstract class PersistedContainer{
  public PersistedContainer(final MontoyaApi api, final String name){
    this(api, name, new DefaultGsonProvider());
  }

  public PersistedContainer(final MontoyaApi api, final String name, final IGsonProvider gsonProvider){
    this(api, name, gsonProvider, (ILogProvider)null);
  }

  public PersistedContainer(final MontoyaApi api, final String name, final ILogProvider logProvider){
    this(api, name, new DefaultGsonProvider(), (ILogProvider)null);
  }

  public PersistedContainer(final MontoyaApi api, final String name, final IGsonProvider gsonProvider, final ILogProvider logProvider){
    this(api, name, gsonProvider, logProvider, "");
  }

  public PersistedContainer(final MontoyaApi api, final String name, final String namespace){
    this(api, name, new DefaultGsonProvider(), namespace);
  }

  public PersistedContainer(final MontoyaApi api, final String name, final IGsonProvider gsonProvider, final String namespace){
    this(api, name, gsonProvider, null, namespace);
  }

  public PersistedContainer(final MontoyaApi api, final String name, final ILogProvider logProvider, final String namespace){
    this(api, name, new DefaultGsonProvider(), logProvider, namespace);
  }

  public PersistedContainer(final MontoyaApi api, final String name, final IGsonProvider gsonProvider, final ILogProvider logProvider, final String namespace){
    _PERSISTED_NAME = name;
    _prefs = new Preferences(api, gsonProvider, logProvider, namespace);
  }

  public void save(){ _prefs.set(_PERSISTED_NAME, this); }

  public void unregister(){ _prefs.unregister(_PERSISTED_NAME); }

  public void reregister(){ _prefs.reregister(_PERSISTED_NAME); }

  protected transient final String        _PERSISTED_NAME;
  protected transient final Preferences   _prefs;
}
