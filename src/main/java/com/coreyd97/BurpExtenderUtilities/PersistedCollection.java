package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;
import com.google.gson.reflect.TypeToken;

import java.util.Collection;
import java.util.Iterator;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Consumer;
import java.util.function.IntFunction;
import java.util.function.Predicate;
import java.util.stream.Stream;

public class PersistedCollection<E, CollectionT extends Collection<E>> implements Collection<E>{
  public PersistedCollection(
    MontoyaApi api,
    String name,
    Preferences.Visibility vis
  ){
    this(api, name, new TypeToken<CollectionT>(){}, vis);
  }

  public PersistedCollection(
    MontoyaApi api,
    String name,
    TypeToken<? extends CollectionT> collectionType,
    Preferences.Visibility vis
  ){
    this(api, name, collectionType, null, vis);
  }

  public PersistedCollection(
    MontoyaApi api,
    String name,
    CollectionT defaultCollection,
    Preferences.Visibility vis
  ){
    this(api, name, new TypeToken<CollectionT>(){}, defaultCollection, vis);
  }

  public PersistedCollection(
    MontoyaApi api,
    String name,
    TypeToken<? extends CollectionT> collectionType, CollectionT defaultCollection,
    Preferences.Visibility vis
  ){
    this(
      api, new DefaultGsonProvider(),
      name,
      collectionType, defaultCollection,
      vis
    );
  }

  public PersistedCollection(
    MontoyaApi api, IGsonProvider gsonProvider,
    String name,
    TypeToken<? extends CollectionT> collectionType, CollectionT defaultCollection,
    Preferences.Visibility vis
  ){
    _PERSISTED_NAME     = name;

    _prefs = new Preferences(api, gsonProvider);
    _prefs.register(name, collectionType.getType(), defaultCollection, vis);

    _internalCollection = _prefs.get(name);
  }

  public void save(){ _prefs.set(_PERSISTED_NAME, this); }

  ////////////////////
  // COLLECTION API //
  ////////////////////
  /**
   * Returns an iterator over the elements contained in this collection.
   *
   * @return an iterator over the elements contained in this collection
   */
  @Override
  public Iterator<E> iterator() {
    return new Iterator<>(){
      private final Iterator<E> internalIterator =
        _internalCollection.iterator();

      @Override
      public boolean hasNext(){ return internalIterator.hasNext(); }

      @Override
      public E next(){ return internalIterator.next(); }

      @Override
      public void remove(){
        internalIterator.remove();
        save();
      }
    };
  }

  /**
   * Performs the given action for each element of the {@code Iterable}
   * until all elements have been processed or the action throws an
   * exception.  Actions are performed in the order of iteration, if that
   * order is specified.  Exceptions thrown by the action are relayed to the
   * caller.
   * <p>
   * The behavior of this method is unspecified if the action performs
   * side-effects that modify the underlying source of elements, unless an
   * overriding class has specified a concurrent modification policy.
   *
   * @param action The action to be performed for each element
   * @throws NullPointerException if the specified action is null
   * @implSpec <p>The default implementation behaves as if:
   * <pre>{@code
   *     for (T t : this)
   *         action.accept(t);
   * }</pre>
   * @since 1.8
   */
  @Override
  public void forEach(Consumer<? super E> action){
    _internalCollection.forEach(action);
  }

  /**
   * Returns an array containing all of the elements in this collection.
   * If this collection makes any guarantees as to what order its elements
   * are returned by its iterator, this method must return the elements in
   * the same order. The returned array's {@linkplain Class#getComponentType
   * runtime component type} is {@code Object}.
   *
   * <p>The returned array will be "safe" in that no references to it are
   * maintained by this collection.  (In other words, this method must
   * allocate a new array even if this collection is backed by an array).
   * The caller is thus free to modify the returned array.
   *
   * @return an array, whose {@linkplain Class#getComponentType runtime component
   * type} is {@code Object}, containing all of the elements in this collection
   * @apiNote This method acts as a bridge between array-based and collection-based APIs.
   * It returns an array whose runtime type is {@code Object[]}.
   * Use {@link #toArray(Object[]) toArray(T[])} to reuse an existing
   * array, or use {@link #toArray(IntFunction)} to control the runtime type
   * of the array.
   */
  @Override
  public Object[] toArray(){
    return _internalCollection.toArray();
  }

  /**
   * Returns an array containing all of the elements in this collection;
   * the runtime type of the returned array is that of the specified array.
   * If the collection fits in the specified array, it is returned therein.
   * Otherwise, a new array is allocated with the runtime type of the
   * specified array and the size of this collection.
   *
   * <p>If this collection fits in the specified array with room to spare
   * (i.e., the array has more elements than this collection), the element
   * in the array immediately following the end of the collection is set to
   * {@code null}.  (This is useful in determining the length of this
   * collection <i>only</i> if the caller knows that this collection does
   * not contain any {@code null} elements.)
   *
   * <p>If this collection makes any guarantees as to what order its elements
   * are returned by its iterator, this method must return the elements in
   * the same order.
   *
   * @param a the array into which the elements of this collection are to be
   *          stored, if it is big enough; otherwise, a new array of the same
   *          runtime type is allocated for this purpose.
   * @return an array containing all of the elements in this collection
   * @throws ArrayStoreException  if the runtime type of any element in this
   *                              collection is not assignable to the {@linkplain Class#getComponentType
   *                              runtime component type} of the specified array
   * @throws NullPointerException if the specified array is null
   * @apiNote This method acts as a bridge between array-based and collection-based APIs.
   * It allows an existing array to be reused under certain circumstances.
   * Use {@link #toArray()} to create an array whose runtime type is {@code Object[]},
   * or use {@link #toArray(IntFunction)} to control the runtime type of
   * the array.
   *
   * <p>Suppose {@code x} is a collection known to contain only strings.
   * The following code can be used to dump the collection into a previously
   * allocated {@code String} array:
   *
   * <pre>
   *     String[] y = new String[SIZE];
   *     ...
   *     y = x.toArray(y);</pre>
   *
   * <p>The return value is reassigned to the variable {@code y}, because a
   * new array will be allocated and returned if the collection {@code x} has
   * too many elements to fit into the existing array {@code y}.
   *
   * <p>Note that {@code toArray(new Object[0])} is identical in function to
   * {@code toArray()}.
   */
  @Override
  public <T> T[] toArray(T[] a){
    return _internalCollection.toArray(a);
  }

  /**
   * Returns an array containing all of the elements in this collection,
   * using the provided {@code generator} function to allocate the returned array.
   *
   * <p>If this collection makes any guarantees as to what order its elements
   * are returned by its iterator, this method must return the elements in
   * the same order.
   *
   * @param generator a function which produces a new array of the desired
   *                  type and the provided length
   * @return an array containing all of the elements in this collection
   * @throws ArrayStoreException  if the runtime type of any element in this
   *                              collection is not assignable to the {@linkplain Class#getComponentType
   *                              runtime component type} of the generated array
   * @throws NullPointerException if the generator function is null
   * @apiNote This method acts as a bridge between array-based and collection-based APIs.
   * It allows creation of an array of a particular runtime type. Use
   * {@link #toArray()} to create an array whose runtime type is {@code Object[]},
   * or use {@link #toArray(Object[]) toArray(T[])} to reuse an existing array.
   *
   * <p>Suppose {@code x} is a collection known to contain only strings.
   * The following code can be used to dump the collection into a newly
   * allocated array of {@code String}:
   *
   * <pre>
   *     String[] y = x.toArray(String[]::new);</pre>
   * @implSpec The default implementation calls the generator function with zero
   * and then passes the resulting array to {@link #toArray(Object[]) toArray(T[])}.
   * @since 11
   */
  @Override
  public <T> T[] toArray(IntFunction<T[]> generator){
    return _internalCollection.toArray(generator);
  }

  @Override
  public int size(){
    return _internalCollection.size();
  }

  /**
   * Returns {@code true} if this collection contains no elements.
   *
   * @return {@code true} if this collection contains no elements
   */
  @Override
  public boolean isEmpty(){
    return _internalCollection.isEmpty();
  }

  /**
   * Returns {@code true} if this collection contains the specified element.
   * More formally, returns {@code true} if and only if this collection
   * contains at least one element {@code e} such that
   * {@code Objects.equals(o, e)}.
   *
   * @param o element whose presence in this collection is to be tested
   * @return {@code true} if this collection contains the specified
   * element
   * @throws ClassCastException   if the type of the specified element
   *                              is incompatible with this collection
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException if the specified element is null and this
   *                              collection does not permit null elements
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   */
  @Override
  public boolean contains(Object o){
    return _internalCollection.contains(o);
  }

  @Override
  public boolean add(E e){
    boolean changed = _internalCollection.add(e);
    if(changed) save();
    return changed;
  }

  /**
   * Removes a single instance of the specified element from this
   * collection, if it is present (optional operation).  More formally,
   * removes an element {@code e} such that
   * {@code Objects.equals(o, e)}, if
   * this collection contains one or more such elements.  Returns
   * {@code true} if this collection contained the specified element (or
   * equivalently, if this collection changed as a result of the call).
   *
   * @param o element to be removed from this collection, if present
   * @return {@code true} if an element was removed as a result of this call
   * @throws ClassCastException            if the type of the specified element
   *                                       is incompatible with this collection
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException          if the specified element is null and this
   *                                       collection does not permit null elements
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws UnsupportedOperationException if the {@code remove} operation
   *                                       is not supported by this collection
   */
  @Override
  public boolean remove(Object o){
    boolean changed = _internalCollection.remove(o);
    if(changed) save();
    return changed;
  }

  /**
   * Returns {@code true} if this collection contains all of the elements
   * in the specified collection.
   *
   * @param c collection to be checked for containment in this collection
   * @return {@code true} if this collection contains all of the elements
   * in the specified collection
   * @throws ClassCastException   if the types of one or more elements
   *                              in the specified collection are incompatible with this
   *                              collection
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException if the specified collection contains one
   *                              or more null elements and this collection does not permit null
   *                              elements
   *                              (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>),
   *                              or if the specified collection is null.
   * @see #contains(Object)
   */
  @Override
  public boolean containsAll(Collection<?> c){
    return _internalCollection.containsAll(c);
  }

  /**
   * Adds all of the elements in the specified collection to this collection
   * (optional operation).  The behavior of this operation is undefined if
   * the specified collection is modified while the operation is in progress.
   * (This implies that the behavior of this call is undefined if the
   * specified collection is this collection, and this collection is
   * nonempty.)
   *
   * @param c collection containing elements to be added to this collection
   * @return {@code true} if this collection changed as a result of the call
   * @throws UnsupportedOperationException if the {@code addAll} operation
   *                                       is not supported by this collection
   * @throws ClassCastException            if the class of an element of the specified
   *                                       collection prevents it from being added to this collection
   * @throws NullPointerException          if the specified collection contains a
   *                                       null element and this collection does not permit null elements,
   *                                       or if the specified collection is null
   * @throws IllegalArgumentException      if some property of an element of the
   *                                       specified collection prevents it from being added to this
   *                                       collection
   * @throws IllegalStateException         if not all the elements can be added at
   *                                       this time due to insertion restrictions
   * @see #add(Object)
   */
  @Override
  public boolean addAll(Collection<? extends E> c){
    boolean changed = _internalCollection.addAll(c);
    if(changed) save();
    return changed;
  }

  /**
   * Removes all of this collection's elements that are also contained in the
   * specified collection (optional operation).  After this call returns,
   * this collection will contain no elements in common with the specified
   * collection.
   *
   * @param c collection containing elements to be removed from this collection
   * @return {@code true} if this collection changed as a result of the
   * call
   * @throws UnsupportedOperationException if the {@code removeAll} method
   *                                       is not supported by this collection
   * @throws ClassCastException            if the types of one or more elements
   *                                       in this collection are incompatible with the specified
   *                                       collection
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException          if this collection contains one or more
   *                                       null elements and the specified collection does not support
   *                                       null elements
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>),
   *                                       or if the specified collection is null
   * @see #remove(Object)
   * @see #contains(Object)
   */
  @Override
  public boolean removeAll(Collection<?> c){
    boolean changed = _internalCollection.removeAll(c);
    if(changed) save();
    return changed;
  }

  /**
   * Removes all of the elements of this collection that satisfy the given
   * predicate.  Errors or runtime exceptions thrown during iteration or by
   * the predicate are relayed to the caller.
   *
   * @param filter a predicate which returns {@code true} for elements to be
   *               removed
   * @return {@code true} if any elements were removed
   * @throws NullPointerException          if the specified filter is null
   * @throws UnsupportedOperationException if elements cannot be removed
   *                                       from this collection.  Implementations may throw this exception if a
   *                                       matching element cannot be removed or if, in general, removal is not
   *                                       supported.
   * @implSpec The default implementation traverses all elements of the collection using
   * its {@link #iterator}.  Each matching element is removed using
   * {@link Iterator#remove()}.  If the collection's iterator does not
   * support removal then an {@code UnsupportedOperationException} will be
   * thrown on the first matching element.
   * @since 1.8
   */
  @Override
  public boolean removeIf(Predicate<? super E> filter){
    boolean changed = _internalCollection.removeIf(filter);
    if(changed) save();
    return changed;
  }

  /**
   * Retains only the elements in this collection that are contained in the
   * specified collection (optional operation).  In other words, removes from
   * this collection all of its elements that are not contained in the
   * specified collection.
   *
   * @param c collection containing elements to be retained in this collection
   * @return {@code true} if this collection changed as a result of the call
   * @throws UnsupportedOperationException if the {@code retainAll} operation
   *                                       is not supported by this collection
   * @throws ClassCastException            if the types of one or more elements
   *                                       in this collection are incompatible with the specified
   *                                       collection
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException          if this collection contains one or more
   *                                       null elements and the specified collection does not permit null
   *                                       elements
   *                                       (<a href="{@docRoot}/java.base/java/util/Collection.html#optional-restrictions">optional</a>),
   *                                       or if the specified collection is null
   * @see #remove(Object)
   * @see #contains(Object)
   */
  @Override
  public boolean retainAll(Collection<?> c){
    boolean changed = _internalCollection.retainAll(c);
    if(changed) save();
    return changed;
  }

  /**
   * Removes all of the elements from this collection (optional operation).
   * The collection will be empty after this method returns.
   *
   * @throws UnsupportedOperationException if the {@code clear} operation
   *                                       is not supported by this collection
   */
  @Override
  public void clear(){
    _internalCollection.clear();
    save();
  }

  /**
   * Creates a {@link Spliterator} over the elements in this collection.
   * <p>
   * Implementations should document characteristic values reported by the
   * spliterator.  Such characteristic values are not required to be reported
   * if the spliterator reports {@link Spliterator#SIZED} and this collection
   * contains no elements.
   *
   * <p>The default implementation should be overridden by subclasses that
   * can return a more efficient spliterator.  In order to
   * preserve expected laziness behavior for the {@link #stream()} and
   * {@link #parallelStream()} methods, spliterators should either have the
   * characteristic of {@code IMMUTABLE} or {@code CONCURRENT}, or be
   * <em><a href="Spliterator.html#binding">late-binding</a></em>.
   * If none of these is practical, the overriding class should describe the
   * spliterator's documented policy of binding and structural interference,
   * and should override the {@link #stream()} and {@link #parallelStream()}
   * methods to create streams using a {@code Supplier} of the spliterator,
   * as in:
   * <pre>{@code
   *     Stream<E> s = StreamSupport.stream(() -> spliterator(), spliteratorCharacteristics)
   * }</pre>
   * <p>These requirements ensure that streams produced by the
   * {@link #stream()} and {@link #parallelStream()} methods will reflect the
   * contents of the collection as of initiation of the terminal stream
   * operation.
   *
   * @return a {@code Spliterator} over the elements in this collection
   * @implSpec The default implementation creates a
   * <em><a href="Spliterator.html#binding">late-binding</a></em> spliterator
   * from the collection's {@code Iterator}.  The spliterator inherits the
   * <em>fail-fast</em> properties of the collection's iterator.
   * <p>
   * The created {@code Spliterator} reports {@link Spliterator#SIZED}.
   * @implNote The created {@code Spliterator} additionally reports
   * {@link Spliterator#SUBSIZED}.
   *
   * <p>If a spliterator covers no elements then the reporting of additional
   * characteristic values, beyond that of {@code SIZED} and {@code SUBSIZED},
   * does not aid clients to control, specialize or simplify computation.
   * However, this does enable shared use of an immutable and empty
   * spliterator instance (see {@link Spliterators#emptySpliterator()}) for
   * empty collections, and enables clients to determine if such a spliterator
   * covers no elements.
   * @since 1.8
   */
  @Override
  public Spliterator<E> spliterator(){
    return _internalCollection.spliterator();
  }

  /**
   * Returns a sequential {@code Stream} with this collection as its source.
   *
   * <p>This method should be overridden when the {@link #spliterator()}
   * method cannot return a spliterator that is {@code IMMUTABLE},
   * {@code CONCURRENT}, or <em>late-binding</em>. (See {@link #spliterator()}
   * for details.)
   *
   * @return a sequential {@code Stream} over the elements in this collection
   * @implSpec The default implementation creates a sequential {@code Stream} from the
   * collection's {@code Spliterator}.
   * @since 1.8
   */
  @Override
  public Stream<E> stream(){
    return _internalCollection.stream();
  }

  /**
   * Returns a possibly parallel {@code Stream} with this collection as its
   * source.  It is allowable for this method to return a sequential stream.
   *
   * <p>This method should be overridden when the {@link #spliterator()}
   * method cannot return a spliterator that is {@code IMMUTABLE},
   * {@code CONCURRENT}, or <em>late-binding</em>. (See {@link #spliterator()}
   * for details.)
   *
   * @return a possibly parallel {@code Stream} over the elements in this
   * collection
   * @implSpec The default implementation creates a parallel {@code Stream} from the
   * collection's {@code Spliterator}.
   * @since 1.8
   */
  @Override
  public Stream<E> parallelStream(){
    return _internalCollection.parallelStream();
  }

  protected final CollectionT _internalCollection;
  protected transient final String      _PERSISTED_NAME;
  protected transient final Preferences _prefs;
}
