package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Type;

//Extending class MUST implement a reflection-accessible no-arg constructor
//  that returns an instance with desired default values set
public abstract class PersistedObject
extends PersistedContainer{
  public PersistedObject(
    MontoyaApi api, String name, Preferences.Visibility vis
  ){
    this(api, name, vis, new DefaultGsonProvider());
  }

  public PersistedObject(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider
  ){
    this(
      api, name, vis,
      new DefaultGsonProvider(), (ILogProvider)null
    );
  }

  public PersistedObject(
    MontoyaApi api, String name, Preferences.Visibility vis,
    ILogProvider logProvider
  ){
    this(
      api, name, vis,
      new DefaultGsonProvider(), logProvider
    );
  }

  public PersistedObject(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider, ILogProvider logProvider
  ){
    this(
      api, name, vis,
      new DefaultGsonProvider(), logProvider,
      ""
    );
  }

  public PersistedObject(
    MontoyaApi api, String name, Preferences.Visibility vis,
    String namespace
  ){
    this(api, name, vis, new DefaultGsonProvider(), namespace);
  }

  public PersistedObject(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider,
    String namespace
  ){
    this(
      api, name, vis,
      new DefaultGsonProvider(), null,
      namespace
    );
  }

  public PersistedObject(
    MontoyaApi api, String name, Preferences.Visibility vis,
    ILogProvider logProvider,
    String namespace
  ){
    this(
      api, name, vis,
      new DefaultGsonProvider(), logProvider,
      namespace
    );
  }

  public PersistedObject(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider, ILogProvider logProvider,
    String namespace
  ){
    super(api, name, gsonProvider, logProvider, namespace);
    _vis = vis;
  }

  /////////////////////
  // PREFERENCES API //
  /////////////////////
  //only resets the internal _prefs object
  //resetting values of data members of child classes
  //  needs to be handled by the child class
  protected void reset(){ _prefs.reset(_PERSISTED_NAME); }

  protected void register(){
    Class<?> thisClazz = this.getClass();
    PersistedObject thisDefaultClone = GsonUtilities.clone(
      this, thisClazz, _prefs.getGsonProvider().getGson()
    );

    this.register(thisClazz, thisDefaultClone);
  }

  protected void register(Type persistedType, Object defaultValue){
    _prefs.register(_PERSISTED_NAME, persistedType, defaultValue, _vis);
  }

  private final transient Preferences.Visibility _vis;
}