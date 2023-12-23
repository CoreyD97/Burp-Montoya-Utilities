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
    MontoyaApi api,
    String name,
    Preferences.Visibility vis
  ){
    this(api, new DefaultGsonProvider(), name, vis);
  }

  public PersistedObject(
    MontoyaApi api, IGsonProvider gsonProvider,
    String name,
    Preferences.Visibility vis
  ){
    super(api, gsonProvider, name);
    _vis = vis;
  }

  /////////////////////
  // PREFERENCES API //
  /////////////////////
  //only resets the internal _prefs object
  //resetting values of data members of child classes
  //  needs to be handled by the child class
  public void reset(){ _prefs.reset(_PERSISTED_NAME); }

  //calls child class no-arg constructor
  //  to get the default value of the object
  protected void register(){
    try{
      Class<?> thisClazz = this.getClass();
      Constructor<?> constr = thisClazz.getDeclaredConstructor();
      constr.setAccessible(true);
      this.register(thisClazz, constr.newInstance());
    }
    catch(NoSuchMethodException | InvocationTargetException |
      InstantiationException | IllegalAccessException e){
      throw new RuntimeException(e);
    }
  }

  protected void register(Type persistedType, Object defaultValue){
    _prefs.register(_PERSISTED_NAME, persistedType, defaultValue, _vis);
  }

  private final transient Preferences.Visibility _vis;

  //DO NOT USE!
  //disabled no-arg constructor
  private PersistedObject(){
    super(null, null, null);
    _vis = null;
  }
}