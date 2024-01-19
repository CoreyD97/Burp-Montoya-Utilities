package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;
import com.google.gson.reflect.TypeToken;

import java.util.AbstractCollection;
import java.util.AbstractSet;
import java.util.Collection;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;

public class PersistedMap<K,V, MapT extends Map<K,V>>
extends PersistedContainer implements Map<K,V>{
  public PersistedMap(
    MontoyaApi api, String name, Preferences.Visibility vis
  ){
    this(api, name, vis, new TypeToken<MapT>(){});
  }

  public PersistedMap(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends MapT> mapType
  ){
    this(api, name, vis, mapType, (MapT)null);
  }

  public PersistedMap(
    MontoyaApi api, String name, Preferences.Visibility vis,
    MapT defaultMap
  ){
    this(api, name, vis, new TypeToken<MapT>(){}, defaultMap);
  }

  public PersistedMap(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends MapT> mapType, MapT defaultMap
  ){
    this(
      api, name, vis,
      new DefaultGsonProvider(),
      mapType, defaultMap
    );
  }

  public PersistedMap(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider,
    TypeToken<? extends MapT> mapType, MapT defaultMap
  ){
    this(
      api, name, vis,
      gsonProvider,
      mapType, defaultMap,
      ""
    );
  }

  public PersistedMap(
    MontoyaApi api, String name, Preferences.Visibility vis,
    String namespace
  ){
    this(api, name, vis, new TypeToken<MapT>(){}, namespace);
  }

  public PersistedMap(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends MapT> mapType,
    String namespace
  ){
    this(api, name, vis, mapType, null, namespace);
  }

  public PersistedMap(
    MontoyaApi api, String name,Preferences.Visibility vis,
    MapT defaultMap,
    String namespace
  ){
    this(api, name, vis, new TypeToken<MapT>(){}, defaultMap, namespace);
  }

  public PersistedMap(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends MapT> mapType, MapT defaultMap,
    String namespace
  ){
    this(
      api, name, vis,
      new DefaultGsonProvider(),
      mapType, defaultMap,
      namespace
    );
  }

  public PersistedMap(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider,
    TypeToken<? extends MapT> mapType, MapT defaultMap,
    String namespace
  ){
    this(
      api, name, vis,
      new DefaultGsonProvider(), null,
      mapType, defaultMap,
      namespace
    );
  }

  public PersistedMap(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider, ILogProvider logProvider,
    TypeToken<? extends MapT> mapType, MapT defaultMap,
    String namespace
  ){
    super(api, name, gsonProvider, logProvider, namespace);
    _prefs.register(name, mapType.getType(), defaultMap, vis);
    _internalMap = _prefs.get(name);
  }

  /////////////////////
  // PREFERENCES API //
  /////////////////////
  public void set(MapT newMap){
    _internalMap = newMap;
    save();
  }

  public void reset(){
    _prefs.reset(_PERSISTED_NAME);
    _internalMap = _prefs.get(_PERSISTED_NAME);
  }

  /////////////
  // MAP API //
  /////////////
  /**
   * Returns the number of key-value mappings in this map.  If the
   * map contains more than {@code Integer.MAX_VALUE} elements, returns
   * {@code Integer.MAX_VALUE}.
   *
   * @return the number of key-value mappings in this map
   */
  @Override
  public int size(){
    return _internalMap.size();
  }

  /**
   * Returns {@code true} if this map contains no key-value mappings.
   *
   * @return {@code true} if this map contains no key-value mappings
   */
  @Override
  public boolean isEmpty(){
    return _internalMap.isEmpty();
  }

  /**
   * Returns {@code true} if this map contains a mapping for the specified
   * key.  More formally, returns {@code true} if and only if
   * this map contains a mapping for a key {@code k} such that
   * {@code Objects.equals(key, k)}.  (There can be
   * at most one such mapping.)
   *
   * @param key key whose presence in this map is to be tested
   * @return {@code true} if this map contains a mapping for the specified
   * key
   * @throws ClassCastException   if the key is of an inappropriate type for
   *                              this map
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException if the specified key is null and this map
   *                              does not permit null keys
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   */
  @Override
  public boolean containsKey(Object key){
    return _internalMap.containsKey(key);
  }

  /**
   * Returns {@code true} if this map maps one or more keys to the
   * specified value.  More formally, returns {@code true} if and only if
   * this map contains at least one mapping to a value {@code v} such that
   * {@code Objects.equals(value, v)}.  This operation
   * will probably require time linear in the map size for most
   * implementations of the {@code Map} interface.
   *
   * @param value value whose presence in this map is to be tested
   * @return {@code true} if this map maps one or more keys to the
   * specified value
   * @throws ClassCastException   if the value is of an inappropriate type for
   *                              this map
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException if the specified value is null and this
   *                              map does not permit null values
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   */
  @Override
  public boolean containsValue(Object value){
    return _internalMap.containsValue(value);
  }

  /**
   * Returns the value to which the specified key is mapped,
   * or {@code null} if this map contains no mapping for the key.
   *
   * <p>More formally, if this map contains a mapping from a key
   * {@code k} to a value {@code v} such that
   * {@code Objects.equals(key, k)},
   * then this method returns {@code v}; otherwise
   * it returns {@code null}.  (There can be at most one such mapping.)
   *
   * <p>If this map permits null values, then a return value of
   * {@code null} does not <i>necessarily</i> indicate that the map
   * contains no mapping for the key; it's also possible that the map
   * explicitly maps the key to {@code null}.  The {@link #containsKey
   * containsKey} operation may be used to distinguish these two cases.
   *
   * @param key the key whose associated value is to be returned
   * @return the value to which the specified key is mapped, or
   * {@code null} if this map contains no mapping for the key
   * @throws ClassCastException   if the key is of an inappropriate type for
   *                              this map
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException if the specified key is null and this map
   *                              does not permit null keys
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   */
  @Override
  public V get(Object key){
    return _internalMap.get(key);
  }

  /**
   * Associates the specified value with the specified key in this map
   * (optional operation).  If the map previously contained a mapping for
   * the key, the old value is replaced by the specified value.  (A map
   * {@code m} is said to contain a mapping for a key {@code k} if and only
   * if {@link #containsKey(Object) m.containsKey(k)} would return
   * {@code true}.)
   *
   * @param key   key with which the specified value is to be associated
   * @param value value to be associated with the specified key
   * @return the previous value associated with {@code key}, or
   * {@code null} if there was no mapping for {@code key}.
   * (A {@code null} return can also indicate that the map
   * previously associated {@code null} with {@code key},
   * if the implementation supports {@code null} values.)
   * @throws UnsupportedOperationException if the {@code put} operation
   *                                       is not supported by this map
   * @throws ClassCastException            if the class of the specified key or value
   *                                       prevents it from being stored in this map
   * @throws NullPointerException          if the specified key or value is null
   *                                       and this map does not permit null keys or values
   * @throws IllegalArgumentException      if some property of the specified key
   *                                       or value prevents it from being stored in this map
   */
  @Override
  public V put(K key, V value){
    V prevVal = _internalMap.put(key, value);
    save();
    return prevVal;
  }

  /**
   * Removes the mapping for a key from this map if it is present
   * (optional operation).   More formally, if this map contains a mapping
   * from key {@code k} to value {@code v} such that
   * {@code Objects.equals(key, k)}, that mapping
   * is removed.  (The map can contain at most one such mapping.)
   *
   * <p>Returns the value to which this map previously associated the key,
   * or {@code null} if the map contained no mapping for the key.
   *
   * <p>If this map permits null values, then a return value of
   * {@code null} does not <i>necessarily</i> indicate that the map
   * contained no mapping for the key; it's also possible that the map
   * explicitly mapped the key to {@code null}.
   *
   * <p>The map will not contain a mapping for the specified key once the
   * call returns.
   *
   * @param key key whose mapping is to be removed from the map
   * @return the previous value associated with {@code key}, or
   * {@code null} if there was no mapping for {@code key}.
   * @throws UnsupportedOperationException if the {@code remove} operation
   *                                       is not supported by this map
   * @throws ClassCastException            if the key is of an inappropriate type for
   *                                       this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException          if the specified key is null and this
   *                                       map does not permit null keys
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   */
  @Override
  public V remove(Object key){
    V prevVal = _internalMap.remove(key);
    save();
    return prevVal;
  }

  /**
   * Copies all of the mappings from the specified map to this map
   * (optional operation).  The effect of this call is equivalent to that
   * of calling {@link #put(Object, Object) put(k, v)} on this map once
   * for each mapping from key {@code k} to value {@code v} in the
   * specified map.  The behavior of this operation is undefined if the
   * specified map is modified while the operation is in progress.
   *
   * @param m mappings to be stored in this map
   * @throws UnsupportedOperationException if the {@code putAll} operation
   *                                       is not supported by this map
   * @throws ClassCastException            if the class of a key or value in the
   *                                       specified map prevents it from being stored in this map
   * @throws NullPointerException          if the specified map is null, or if
   *                                       this map does not permit null keys or values, and the
   *                                       specified map contains null keys or values
   * @throws IllegalArgumentException      if some property of a key or value in
   *                                       the specified map prevents it from being stored in this map
   */
  @Override
  public void putAll(Map<? extends K, ? extends V> m){
    _internalMap.putAll(m);
    save();
  }

  /**
   * Removes all of the mappings from this map (optional operation).
   * The map will be empty after this call returns.
   *
   * @throws UnsupportedOperationException if the {@code clear} operation
   *                                       is not supported by this map
   */
  @Override
  public void clear(){
    _internalMap.clear();
    save();
  }

  /**
   * Returns a {@link Set} view of the keys contained in this map.
   * The set is backed by the map, so changes to the map are
   * reflected in the set, and vice-versa.  If the map is modified
   * while an iteration over the set is in progress (except through
   * the iterator's own {@code remove} operation), the results of
   * the iteration are undefined.  The set supports element removal,
   * which removes the corresponding mapping from the map, via the
   * {@code Iterator.remove}, {@code Set.remove},
   * {@code removeAll}, {@code retainAll}, and {@code clear}
   * operations.  It does not support the {@code add} or {@code addAll}
   * operations.
   *
   * @return a set view of the keys contained in this map
   */
  @Override
  public Set<K> keySet(){
    Set<K> ks = keySet;
    if (ks == null) {
      ks = new AbstractSet<K>() {
        public Iterator<K> iterator() {
          return new Iterator<K>() {
            private Iterator<Entry<K,V>> i = entrySet().iterator();

            public boolean hasNext() {
              return i.hasNext();
            }

            public K next() {
              return i.next().getKey();
            }

            public void remove() {
              i.remove();
              PersistedMap.this.save();
            }
          };
        }

        public int size() {
          return PersistedMap.this.size();
        }

        public boolean isEmpty() {
          return PersistedMap.this.isEmpty();
        }

        public void clear() {
          PersistedMap.this.clear();
        }

        public boolean contains(Object k) {
          return PersistedMap.this.containsKey(k);
        }
      };
      keySet = ks;
    }
    return ks;
  }

  /**
   * Returns a {@link Collection} view of the values contained in this map.
   * The collection is backed by the map, so changes to the map are
   * reflected in the collection, and vice-versa.  If the map is
   * modified while an iteration over the collection is in progress
   * (except through the iterator's own {@code remove} operation),
   * the results of the iteration are undefined.  The collection
   * supports element removal, which removes the corresponding
   * mapping from the map, via the {@code Iterator.remove},
   * {@code Collection.remove}, {@code removeAll},
   * {@code retainAll} and {@code clear} operations.  It does not
   * support the {@code add} or {@code addAll} operations.
   *
   * @return a collection view of the values contained in this map
   */
  @Override
  public Collection<V> values(){
    Collection<V> vals = values;
    if (vals == null) {
      vals = new AbstractCollection<V>() {
        public Iterator<V> iterator() {
          return new Iterator<V>() {
            private Iterator<Entry<K,V>> i = entrySet().iterator();

            public boolean hasNext() {
              return i.hasNext();
            }

            public V next() {
              return i.next().getValue();
            }

            public void remove() {
              i.remove();
              PersistedMap.this.save();
            }
          };
        }

        public int size() {
          return PersistedMap.this.size();
        }

        public boolean isEmpty() {
          return PersistedMap.this.isEmpty();
        }

        public void clear() {
          PersistedMap.this.clear();
        }

        public boolean contains(Object v) {
          return PersistedMap.this.containsValue(v);
        }
      };
      values = vals;
    }
    return vals;
  }

  /**
   * Returns a {@link Set} view of the mappings contained in this map.
   * The set is backed by the map, so changes to the map are
   * reflected in the set, and vice-versa.  If the map is modified
   * while an iteration over the set is in progress (except through
   * the iterator's own {@code remove} operation, or through the
   * {@code setValue} operation on a map entry returned by the
   * iterator) the results of the iteration are undefined.  The set
   * supports element removal, which removes the corresponding
   * mapping from the map, via the {@code Iterator.remove},
   * {@code Set.remove}, {@code removeAll}, {@code retainAll} and
   * {@code clear} operations.  It does not support the
   * {@code add} or {@code addAll} operations.
   *
   * @return a set view of the mappings contained in this map
   */
  @Override
  public Set<Entry<K, V>> entrySet(){
    Set<Map.Entry<K,V>> es;
    return (es = entrySet) == null ?
      (entrySet = new PersistedMap<K,V, Map<K,V>>.EntrySet()) :
      es;
  }

  /**
   * Returns the value to which the specified key is mapped, or
   * {@code defaultValue} if this map contains no mapping for the key.
   *
   * @param key          the key whose associated value is to be returned
   * @param defaultValue the default mapping of the key
   * @return the value to which the specified key is mapped, or
   * {@code defaultValue} if this map contains no mapping for the key
   * @throws ClassCastException   if the key is of an inappropriate type for
   *                              this map
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException if the specified key is null and this map
   *                              does not permit null keys
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @implSpec The default implementation makes no guarantees about synchronization
   * or atomicity properties of this method. Any implementation providing
   * atomicity guarantees must override this method and document its
   * concurrency properties.
   * @since 1.8
   */
  @Override
  public V getOrDefault(Object key, V defaultValue){
    return _internalMap.getOrDefault(key, defaultValue);
  }

  /**
   * Performs the given action for each entry in this map until all entries
   * have been processed or the action throws an exception.   Unless
   * otherwise specified by the implementing class, actions are performed in
   * the order of entry set iteration (if an iteration order is specified.)
   * Exceptions thrown by the action are relayed to the caller.
   *
   * @param action The action to be performed for each entry
   * @throws NullPointerException            if the specified action is null
   * @throws ConcurrentModificationException if an entry is found to be
   *                                         removed during iteration
   * @implSpec The default implementation is equivalent to, for this {@code map}:
   * <pre> {@code
   * for (Map.Entry<K, V> entry : map.entrySet())
   *     action.accept(entry.getKey(), entry.getValue());
   * }</pre>
   * <p>
   * The default implementation makes no guarantees about synchronization
   * or atomicity properties of this method. Any implementation providing
   * atomicity guarantees must override this method and document its
   * concurrency properties.
   * @since 1.8
   */
  @Override
  public void forEach(BiConsumer<? super K, ? super V> action){
    _internalMap.forEach(action);
  }

  /**
   * Replaces each entry's value with the result of invoking the given
   * function on that entry until all entries have been processed or the
   * function throws an exception.  Exceptions thrown by the function are
   * relayed to the caller.
   *
   * @param function the function to apply to each entry
   * @throws UnsupportedOperationException   if the {@code set} operation
   *                                         is not supported by this map's entry set iterator.
   * @throws ClassCastException              if the class of a replacement value
   *                                         prevents it from being stored in this map
   * @throws NullPointerException            if the specified function is null, or the
   *                                         specified replacement value is null, and this map does not permit null
   *                                         values
   * @throws ClassCastException              if a replacement value is of an inappropriate
   *                                         type for this map
   *                                         (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException            if function or a replacement value is null,
   *                                         and this map does not permit null keys or values
   *                                         (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws IllegalArgumentException        if some property of a replacement value
   *                                         prevents it from being stored in this map
   *                                         (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws ConcurrentModificationException if an entry is found to be
   *                                         removed during iteration
   * @implSpec <p>The default implementation is equivalent to, for this {@code map}:
   * <pre> {@code
   * for (Map.Entry<K, V> entry : map.entrySet())
   *     entry.setValue(function.apply(entry.getKey(), entry.getValue()));
   * }</pre>
   *
   * <p>The default implementation makes no guarantees about synchronization
   * or atomicity properties of this method. Any implementation providing
   * atomicity guarantees must override this method and document its
   * concurrency properties.
   * @since 1.8
   */
  @Override
  public void replaceAll(
    BiFunction<? super K, ? super V, ? extends V> function
  ){
    _internalMap.replaceAll(function);
    save();
  }

  /**
   * If the specified key is not already associated with a value (or is mapped
   * to {@code null}) associates it with the given value and returns
   * {@code null}, else returns the current value.
   *
   * @param key   key with which the specified value is to be associated
   * @param value value to be associated with the specified key
   * @return the previous value associated with the specified key, or
   * {@code null} if there was no mapping for the key.
   * (A {@code null} return can also indicate that the map
   * previously associated {@code null} with the key,
   * if the implementation supports null values.)
   * @throws UnsupportedOperationException if the {@code put} operation
   *                                       is not supported by this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws ClassCastException            if the key or value is of an inappropriate
   *                                       type for this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException          if the specified key or value is null,
   *                                       and this map does not permit null keys or values
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws IllegalArgumentException      if some property of the specified key
   *                                       or value prevents it from being stored in this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @implSpec The default implementation is equivalent to, for this {@code map}:
   *
   * <pre> {@code
   * V v = map.get(key);
   * if (v == null)
   *     v = map.put(key, value);
   *
   * return v;
   * }</pre>
   *
   * <p>The default implementation makes no guarantees about synchronization
   * or atomicity properties of this method. Any implementation providing
   * atomicity guarantees must override this method and document its
   * concurrency properties.
   * @since 1.8
   */
  @Override
  public V putIfAbsent(K key, V value){
    V prevVal = _internalMap.putIfAbsent(key, value);
    save();
    return prevVal;
  }

  /**
   * Removes the entry for the specified key only if it is currently
   * mapped to the specified value.
   *
   * @param key   key with which the specified value is associated
   * @param value value expected to be associated with the specified key
   * @return {@code true} if the value was removed
   * @throws UnsupportedOperationException if the {@code remove} operation
   *                                       is not supported by this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws ClassCastException            if the key or value is of an inappropriate
   *                                       type for this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException          if the specified key or value is null,
   *                                       and this map does not permit null keys or values
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @implSpec The default implementation is equivalent to, for this {@code map}:
   *
   * <pre> {@code
   * if (map.containsKey(key) && Objects.equals(map.get(key), value)) {
   *     map.remove(key);
   *     return true;
   * } else
   *     return false;
   * }</pre>
   *
   * <p>The default implementation makes no guarantees about synchronization
   * or atomicity properties of this method. Any implementation providing
   * atomicity guarantees must override this method and document its
   * concurrency properties.
   * @since 1.8
   */
  @Override
  public boolean remove(Object key, Object value){
    boolean changed = _internalMap.remove(key, value);
    if(changed) save();
    return changed;
  }

  /**
   * Replaces the entry for the specified key only if currently
   * mapped to the specified value.
   *
   * @param key      key with which the specified value is associated
   * @param oldValue value expected to be associated with the specified key
   * @param newValue value to be associated with the specified key
   * @return {@code true} if the value was replaced
   * @throws UnsupportedOperationException if the {@code put} operation
   *                                       is not supported by this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws ClassCastException            if the class of a specified key or value
   *                                       prevents it from being stored in this map
   * @throws NullPointerException          if a specified key or newValue is null,
   *                                       and this map does not permit null keys or values
   * @throws NullPointerException          if oldValue is null and this map does not
   *                                       permit null values
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws IllegalArgumentException      if some property of a specified key
   *                                       or value prevents it from being stored in this map
   * @implSpec The default implementation is equivalent to, for this {@code map}:
   *
   * <pre> {@code
   * if (map.containsKey(key) && Objects.equals(map.get(key), oldValue)) {
   *     map.put(key, newValue);
   *     return true;
   * } else
   *     return false;
   * }</pre>
   * <p>
   * The default implementation does not throw NullPointerException
   * for maps that do not support null values if oldValue is null unless
   * newValue is also null.
   *
   * <p>The default implementation makes no guarantees about synchronization
   * or atomicity properties of this method. Any implementation providing
   * atomicity guarantees must override this method and document its
   * concurrency properties.
   * @since 1.8
   */
  @Override
  public boolean replace(K key, V oldValue, V newValue){
    boolean changed = _internalMap.replace(key, oldValue, newValue);
    if(changed) save();
    return changed;
  }

  /**
   * Replaces the entry for the specified key only if it is
   * currently mapped to some value.
   *
   * @param key   key with which the specified value is associated
   * @param value value to be associated with the specified key
   * @return the previous value associated with the specified key, or
   * {@code null} if there was no mapping for the key.
   * (A {@code null} return can also indicate that the map
   * previously associated {@code null} with the key,
   * if the implementation supports null values.)
   * @throws UnsupportedOperationException if the {@code put} operation
   *                                       is not supported by this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws ClassCastException            if the class of the specified key or value
   *                                       prevents it from being stored in this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException          if the specified key or value is null,
   *                                       and this map does not permit null keys or values
   * @throws IllegalArgumentException      if some property of the specified key
   *                                       or value prevents it from being stored in this map
   * @implSpec The default implementation is equivalent to, for this {@code map}:
   *
   * <pre> {@code
   * if (map.containsKey(key)) {
   *     return map.put(key, value);
   * } else
   *     return null;
   * }</pre>
   *
   * <p>The default implementation makes no guarantees about synchronization
   * or atomicity properties of this method. Any implementation providing
   * atomicity guarantees must override this method and document its
   * concurrency properties.
   * @since 1.8
   */
  @Override
  public V replace(K key, V value){
    V prevVal = _internalMap.replace(key, value);
    save();
    return prevVal;
  }

  /**
   * If the specified key is not already associated with a value (or is mapped
   * to {@code null}), attempts to compute its value using the given mapping
   * function and enters it into this map unless {@code null}.
   *
   * <p>If the mapping function returns {@code null}, no mapping is recorded.
   * If the mapping function itself throws an (unchecked) exception, the
   * exception is rethrown, and no mapping is recorded.  The most
   * common usage is to construct a new object serving as an initial
   * mapped value or memoized result, as in:
   *
   * <pre> {@code
   * map.computeIfAbsent(key, k -> new Value(f(k)));
   * }</pre>
   *
   * <p>Or to implement a multi-value map, {@code Map<K,Collection<V>>},
   * supporting multiple values per key:
   *
   * <pre> {@code
   * map.computeIfAbsent(key, k -> new HashSet<V>()).add(v);
   * }</pre>
   *
   * <p>The mapping function should not modify this map during computation.
   *
   * @param key             key with which the specified value is to be associated
   * @param mappingFunction the mapping function to compute a value
   * @return the current (existing or computed) value associated with
   * the specified key, or null if the computed value is null
   * @throws NullPointerException          if the specified key is null and
   *                                       this map does not support null keys, or the mappingFunction
   *                                       is null
   * @throws UnsupportedOperationException if the {@code put} operation
   *                                       is not supported by this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws ClassCastException            if the class of the specified key or value
   *                                       prevents it from being stored in this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws IllegalArgumentException      if some property of the specified key
   *                                       or value prevents it from being stored in this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @implSpec The default implementation is equivalent to the following steps for this
   * {@code map}, then returning the current value or {@code null} if now
   * absent:
   *
   * <pre> {@code
   * if (map.get(key) == null) {
   *     V newValue = mappingFunction.apply(key);
   *     if (newValue != null)
   *         map.put(key, newValue);
   * }
   * }</pre>
   *
   * <p>The default implementation makes no guarantees about detecting if the
   * mapping function modifies this map during computation and, if
   * appropriate, reporting an error. Non-concurrent implementations should
   * override this method and, on a best-effort basis, throw a
   * {@code ConcurrentModificationException} if it is detected that the
   * mapping function modifies this map during computation. Concurrent
   * implementations should override this method and, on a best-effort basis,
   * throw an {@code IllegalStateException} if it is detected that the
   * mapping function modifies this map during computation and as a result
   * computation would never complete.
   *
   * <p>The default implementation makes no guarantees about synchronization
   * or atomicity properties of this method. Any implementation providing
   * atomicity guarantees must override this method and document its
   * concurrency properties. In particular, all implementations of
   * subinterface {@link ConcurrentMap} must document
   * whether the mapping function is applied once atomically only if the value
   * is not present.
   * @since 1.8
   */
  @Override
  public V computeIfAbsent(
    K key, Function<? super K, ? extends V> mappingFunction
  ){
    V val = _internalMap.computeIfAbsent(key, mappingFunction);
    save();
    return val;
  }

  /**
   * If the value for the specified key is present and non-null, attempts to
   * compute a new mapping given the key and its current mapped value.
   *
   * <p>If the remapping function returns {@code null}, the mapping is removed.
   * If the remapping function itself throws an (unchecked) exception, the
   * exception is rethrown, and the current mapping is left unchanged.
   *
   * <p>The remapping function should not modify this map during computation.
   *
   * @param key               key with which the specified value is to be associated
   * @param remappingFunction the remapping function to compute a value
   * @return the new value associated with the specified key, or null if none
   * @throws NullPointerException          if the specified key is null and
   *                                       this map does not support null keys, or the
   *                                       remappingFunction is null
   * @throws UnsupportedOperationException if the {@code put} operation
   *                                       is not supported by this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws ClassCastException            if the class of the specified key or value
   *                                       prevents it from being stored in this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws IllegalArgumentException      if some property of the specified key
   *                                       or value prevents it from being stored in this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @implSpec The default implementation is equivalent to performing the following
   * steps for this {@code map}, then returning the current value or
   * {@code null} if now absent:
   *
   * <pre> {@code
   * if (map.get(key) != null) {
   *     V oldValue = map.get(key);
   *     V newValue = remappingFunction.apply(key, oldValue);
   *     if (newValue != null)
   *         map.put(key, newValue);
   *     else
   *         map.remove(key);
   * }
   * }</pre>
   *
   * <p>The default implementation makes no guarantees about detecting if the
   * remapping function modifies this map during computation and, if
   * appropriate, reporting an error. Non-concurrent implementations should
   * override this method and, on a best-effort basis, throw a
   * {@code ConcurrentModificationException} if it is detected that the
   * remapping function modifies this map during computation. Concurrent
   * implementations should override this method and, on a best-effort basis,
   * throw an {@code IllegalStateException} if it is detected that the
   * remapping function modifies this map during computation and as a result
   * computation would never complete.
   *
   * <p>The default implementation makes no guarantees about synchronization
   * or atomicity properties of this method. Any implementation providing
   * atomicity guarantees must override this method and document its
   * concurrency properties. In particular, all implementations of
   * subinterface {@link ConcurrentMap} must document
   * whether the remapping function is applied once atomically only if the
   * value is not present.
   * @since 1.8
   */
  @Override
  public V computeIfPresent(
    K key, BiFunction<? super K, ? super V, ? extends V> remappingFunction
  ){
    V newVal = _internalMap.computeIfPresent(key, remappingFunction);
    save();
    return newVal;
  }

  /**
   * Attempts to compute a mapping for the specified key and its current
   * mapped value (or {@code null} if there is no current mapping). For
   * example, to either create or append a {@code String} msg to a value
   * mapping:
   *
   * <pre> {@code
   * map.compute(key, (k, v) -> (v == null) ? msg : v.concat(msg))}</pre>
   * (Method {@link #merge merge()} is often simpler to use for such purposes.)
   *
   * <p>If the remapping function returns {@code null}, the mapping is removed
   * (or remains absent if initially absent).  If the remapping function
   * itself throws an (unchecked) exception, the exception is rethrown, and
   * the current mapping is left unchanged.
   *
   * <p>The remapping function should not modify this map during computation.
   *
   * @param key               key with which the specified value is to be associated
   * @param remappingFunction the remapping function to compute a value
   * @return the new value associated with the specified key, or null if none
   * @throws NullPointerException          if the specified key is null and
   *                                       this map does not support null keys, or the
   *                                       remappingFunction is null
   * @throws UnsupportedOperationException if the {@code put} operation
   *                                       is not supported by this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws ClassCastException            if the class of the specified key or value
   *                                       prevents it from being stored in this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws IllegalArgumentException      if some property of the specified key
   *                                       or value prevents it from being stored in this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @implSpec The default implementation is equivalent to performing the following
   * steps for this {@code map}:
   *
   * <pre> {@code
   * V oldValue = map.get(key);
   * V newValue = remappingFunction.apply(key, oldValue);
   * if (newValue != null) {
   *     map.put(key, newValue);
   * } else if (oldValue != null || map.containsKey(key)) {
   *     map.remove(key);
   * }
   * return newValue;
   * }</pre>
   *
   * <p>The default implementation makes no guarantees about detecting if the
   * remapping function modifies this map during computation and, if
   * appropriate, reporting an error. Non-concurrent implementations should
   * override this method and, on a best-effort basis, throw a
   * {@code ConcurrentModificationException} if it is detected that the
   * remapping function modifies this map during computation. Concurrent
   * implementations should override this method and, on a best-effort basis,
   * throw an {@code IllegalStateException} if it is detected that the
   * remapping function modifies this map during computation and as a result
   * computation would never complete.
   *
   * <p>The default implementation makes no guarantees about synchronization
   * or atomicity properties of this method. Any implementation providing
   * atomicity guarantees must override this method and document its
   * concurrency properties. In particular, all implementations of
   * subinterface {@link ConcurrentMap} must document
   * whether the remapping function is applied once atomically only if the
   * value is not present.
   * @since 1.8
   */
  @Override
  public V compute(
    K key, BiFunction<? super K, ? super V, ? extends V> remappingFunction
  ){
    V newVal = _internalMap.compute(key, remappingFunction);
    save();
    return newVal;
  }

  /**
   * If the specified key is not already associated with a value or is
   * associated with null, associates it with the given non-null value.
   * Otherwise, replaces the associated value with the results of the given
   * remapping function, or removes if the result is {@code null}. This
   * method may be of use when combining multiple mapped values for a key.
   * For example, to either create or append a {@code String msg} to a
   * value mapping:
   *
   * <pre> {@code
   * map.merge(key, msg, String::concat)
   * }</pre>
   *
   * <p>If the remapping function returns {@code null}, the mapping is removed.
   * If the remapping function itself throws an (unchecked) exception, the
   * exception is rethrown, and the current mapping is left unchanged.
   *
   * <p>The remapping function should not modify this map during computation.
   *
   * @param key               key with which the resulting value is to be associated
   * @param value             the non-null value to be merged with the existing value
   *                          associated with the key or, if no existing value or a null value
   *                          is associated with the key, to be associated with the key
   * @param remappingFunction the remapping function to recompute a value if
   *                          present
   * @return the new value associated with the specified key, or null if no
   * value is associated with the key
   * @throws UnsupportedOperationException if the {@code put} operation
   *                                       is not supported by this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws ClassCastException            if the class of the specified key or value
   *                                       prevents it from being stored in this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws IllegalArgumentException      if some property of the specified key
   *                                       or value prevents it from being stored in this map
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException          if the specified key is null and this map
   *                                       does not support null keys or the value or remappingFunction is
   *                                       null
   * @implSpec The default implementation is equivalent to performing the following
   * steps for this {@code map}, then returning the current value or
   * {@code null} if absent:
   *
   * <pre> {@code
   * V oldValue = map.get(key);
   * V newValue = (oldValue == null) ? value :
   *              remappingFunction.apply(oldValue, value);
   * if (newValue == null)
   *     map.remove(key);
   * else
   *     map.put(key, newValue);
   * }</pre>
   *
   * <p>The default implementation makes no guarantees about detecting if the
   * remapping function modifies this map during computation and, if
   * appropriate, reporting an error. Non-concurrent implementations should
   * override this method and, on a best-effort basis, throw a
   * {@code ConcurrentModificationException} if it is detected that the
   * remapping function modifies this map during computation. Concurrent
   * implementations should override this method and, on a best-effort basis,
   * throw an {@code IllegalStateException} if it is detected that the
   * remapping function modifies this map during computation and as a result
   * computation would never complete.
   *
   * <p>The default implementation makes no guarantees about synchronization
   * or atomicity properties of this method. Any implementation providing
   * atomicity guarantees must override this method and document its
   * concurrency properties. In particular, all implementations of
   * subinterface {@link ConcurrentMap} must document
   * whether the remapping function is applied once atomically only if the
   * value is not present.
   * @since 1.8
   */
  @Override
  public V merge(
    K key, V value,
    BiFunction<? super V, ? super V, ? extends V> remappingFunction
  ){
    V newVal = _internalMap.merge(key, value, remappingFunction);
    save();
    return newVal;
  }

  /**
   * Each of these fields are initialized to contain an instance of the
   * appropriate view the first time this view is requested.  The views are
   * stateless, so there's no reason to create more than one of each.
   *
   * <p>Since there is no synchronization performed while accessing these fields,
   * it is expected that java.util.Map view classes using these fields have
   * no non-final fields (or any fields at all except for outer-this). Adhering
   * to this rule would make the races on these fields benign.
   *
   * <p>It is also imperative that implementations read the field only once,
   * as in:
   *
   * <pre> {@code
   * public Set<K> keySet() {
   *   Set<K> ks = keySet;  // single racy read
   *   if (ks == null) {
   *     ks = new KeySet();
   *     keySet = ks;
   *   }
   *   return ks;
   * }
   *}</pre>
   */
  transient Set<K>          keySet;
  transient Collection<V>   values;
  transient Set<Entry<K,V>> entrySet;

  final class EntrySet extends AbstractSet<Entry<K,V>> {
    public EntrySet(){
      _internalEntrySet = PersistedMap.this._internalMap.entrySet();
    }
    @Override
    public final int size()   { return _internalEntrySet.size(); }
    @Override
    public final void clear() { PersistedMap.this.clear(); }
    @Override
    public final Iterator<Entry<K,V>> iterator() {
      return new PersistedMap<K,V, Map<K,V>>.EntryIterator(_internalEntrySet.iterator());
    }
    @Override
    public final boolean contains(Object o) {
      return _internalEntrySet.contains(o);
    }
    @Override
    public final boolean remove(Object o) {
      boolean prevContained = _internalEntrySet.remove(o);
      if(prevContained) PersistedMap.this.save();
      return prevContained;
    }
    @Override
    public final void forEach(Consumer<? super Entry<K,V>> action) {
      _internalEntrySet.forEach(action);
    }

    private Set<Entry<K,V>> _internalEntrySet;
  }

  final class EntryIterator implements Iterator<Entry<K,V>>{
    public EntryIterator(Iterator<Entry<K,V>> internalIterator){
      _internalEntryIterator = internalIterator;
    }

    @Override
    public boolean hasNext(){
      return _internalEntryIterator.hasNext();
    }

    @Override
    public Entry<K, V> next(){
      return _internalEntryIterator.next();
    }

    @Override
    public void remove(){
      _internalEntryIterator.remove();
      PersistedMap.this.save();
    }

    private Iterator<Entry<K,V>> _internalEntryIterator;
  }

  protected MapT _internalMap;
}
