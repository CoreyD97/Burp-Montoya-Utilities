package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;
import com.google.gson.reflect.TypeToken;

import java.util.Set;

public class PersistedSet<E> extends PersistedCollection<E, Set<E>> implements Set<E>{
  public PersistedSet(
    MontoyaApi api,
    String name,
    Preferences.Visibility vis
  ){
    super(api, name, new TypeToken<Set<E>>(){}, vis);
  }

  public PersistedSet(
    MontoyaApi api,
    String name,
    TypeToken<? extends Set<E>> setType,
    Preferences.Visibility vis
  ){
    super(api, name, setType, vis);
  }

  public PersistedSet(
    MontoyaApi api,
    String name,
    Set<E> defaultSet,
    Preferences.Visibility vis
  ){
    super(api, name, new TypeToken<Set<E>>(){}, defaultSet, vis);
  }

  public PersistedSet(
    MontoyaApi api,
    String name,
    TypeToken<? extends Set<E>> setType, Set<E> defaultSet,
    Preferences.Visibility vis
  ){
    super(api, name, setType, defaultSet, vis);
  }

  public PersistedSet(
    MontoyaApi api, IGsonProvider gsonProvider,
    String name,
    TypeToken<? extends Set<E>> setType, Set<E> defaultSet,
    Preferences.Visibility vis
  ){
    super(api, gsonProvider, name, setType, defaultSet, vis);
  }
}
