package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;
import com.google.gson.reflect.TypeToken;

import java.util.Set;

public class PersistedSet<E> extends PersistedCollection<E, Set<E>> implements Set<E>{
  public PersistedSet(
    final MontoyaApi api, final String name, final Preferences.Visibility vis
  ){
    super(api, name, vis, new TypeToken<Set<E>>(){});
  }

  public PersistedSet(
    final MontoyaApi api, final String name, final Preferences.Visibility vis,
    final TypeToken<? extends Set<E>> setType
  ){
    super(api, name, vis, setType);
  }

  public PersistedSet(
    final MontoyaApi api, final String name, final Preferences.Visibility vis,
    final Set<E> defaultSet
  ){
    super(api, name, vis, new TypeToken<Set<E>>(){}, defaultSet);
  }

  public PersistedSet(
    final MontoyaApi api, final String name, final Preferences.Visibility vis,
    final TypeToken<? extends Set<E>> setType, final Set<E> defaultSet
  ){
    super(api, name, vis, setType, defaultSet);
  }

  public PersistedSet(
    final MontoyaApi api, final String name, final Preferences.Visibility vis,
    final IGsonProvider gsonProvider,
    final TypeToken<? extends Set<E>> setType, final Set<E> defaultSet
  ){
    super(api, name, vis, gsonProvider, setType, defaultSet);
  }

  public PersistedSet(
    final MontoyaApi api, final String name, final Preferences.Visibility vis,
    final String namespace
  ){
    super(api, name, vis, new TypeToken<Set<E>>(){}, namespace);
  }

  public PersistedSet(
    final MontoyaApi api, final String name, final Preferences.Visibility vis,
    final TypeToken<? extends Set<E>> setType,
    final String namespace
  ){
    super(api, name, vis, setType, null, namespace);
  }

  public PersistedSet(
    final MontoyaApi api, final String name, final Preferences.Visibility vis,
    final Set<E> defaultSet,
    final String namespace
  ){
    super(api, name, vis, new TypeToken<Set<E>>(){}, defaultSet, namespace);
  }

  public PersistedSet(
    final MontoyaApi api, final String name, final Preferences.Visibility vis,
    final TypeToken<? extends Set<E>> setType, final Set<E> defaultSet,
    final String namespace
  ){
    super(
      api, name, vis,
      new DefaultGsonProvider(),
      setType, defaultSet,
      namespace
    );
  }

  public PersistedSet(
    final MontoyaApi api, final String name, final Preferences.Visibility vis,
    final IGsonProvider gsonProvider,
    final TypeToken<? extends Set<E>> setType, final Set<E> defaultSet,
    final String namespace
  ){
    super(
      api, name, vis,
      gsonProvider, null,
      setType, defaultSet,
      namespace
    );
  }

  public PersistedSet(
    final MontoyaApi api, final String name, final Preferences.Visibility vis,
    final IGsonProvider gsonProvider, final ILogProvider logProvider,
    final TypeToken<? extends Set<E>> setType, final Set<E> defaultSet,
    final String namespace
  ){
    super(
      api, name, vis,
      gsonProvider, logProvider,
      setType, defaultSet,
      namespace
    );
  }
}
