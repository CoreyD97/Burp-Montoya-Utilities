package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;
import com.google.gson.reflect.TypeToken;

import java.util.Set;

public class PersistedSet<E> extends PersistedCollection<E, Set<E>> implements Set<E>{
  public PersistedSet(
    MontoyaApi api, String name, Preferences.Visibility vis
  ){
    super(api, name, vis, new TypeToken<Set<E>>(){});
  }

  public PersistedSet(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends Set<E>> setType
  ){
    super(api, name, vis, setType);
  }

  public PersistedSet(
    MontoyaApi api, String name, Preferences.Visibility vis,
    Set<E> defaultSet
  ){
    super(api, name, vis, new TypeToken<Set<E>>(){}, defaultSet);
  }

  public PersistedSet(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends Set<E>> setType, Set<E> defaultSet
  ){
    super(api, name, vis, setType, defaultSet);
  }

  public PersistedSet(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider,
    TypeToken<? extends Set<E>> setType, Set<E> defaultSet
  ){
    super(api, name, vis, gsonProvider, setType, defaultSet);
  }

  public PersistedSet(
    MontoyaApi api, String name, Preferences.Visibility vis,
    String namespace
  ){
    super(api, name, vis, new TypeToken<Set<E>>(){}, namespace);
  }

  public PersistedSet(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends Set<E>> setType,
    String namespace
  ){
    super(api, name, vis, setType, null, namespace);
  }

  public PersistedSet(
    MontoyaApi api, String name, Preferences.Visibility vis,
    Set<E> defaultSet,
    String namespace
  ){
    super(api, name, vis, new TypeToken<Set<E>>(){}, defaultSet, namespace);
  }

  public PersistedSet(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends Set<E>> setType, Set<E> defaultSet,
    String namespace
  ){
    super(
      api, name, vis,
      new DefaultGsonProvider(),
      setType, defaultSet,
      namespace
    );
  }

  public PersistedSet(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider,
    TypeToken<? extends Set<E>> setType, Set<E> defaultSet,
    String namespace
  ){
    super(
      api, name, vis,
      new DefaultGsonProvider(), null,
      setType, defaultSet,
      namespace
    );
  }

  public PersistedSet(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider, ILogProvider logProvider,
    TypeToken<? extends Set<E>> setType, Set<E> defaultSet,
    String namespace
  ){
    super(
      api, name, vis,
      gsonProvider, logProvider,
      setType, defaultSet,
      namespace
    );
  }
}
