package com.coreyd97.BurpExtenderUtilities;

import burp.api.montoya.MontoyaApi;
import com.google.gson.reflect.TypeToken;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.ListIterator;
import java.util.function.UnaryOperator;

public class PersistedList<E> extends PersistedCollection<E, List<E>> implements List<E>{
  public PersistedList(
    MontoyaApi api, String name, Preferences.Visibility vis
  ){
    super(api, name, vis, new TypeToken<List<E>>(){});
  }

  public PersistedList(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends List<E>> listType
  ){
    super(api, name, vis, listType);
  }

  public PersistedList(
    MontoyaApi api, String name, Preferences.Visibility vis,
    List<E> defaultList
  ){
    super(api, name, vis, new TypeToken<List<E>>(){}, defaultList);
  }

  public PersistedList(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends List<E>> listType, List<E> defaultList
  ){
    super(api, name, vis, listType, defaultList);
  }

  public PersistedList(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider,
    TypeToken<? extends List<E>> listType, List<E> defaultList
  ){
    super(api, name, vis, gsonProvider, listType, defaultList);
  }

  public PersistedList(
    MontoyaApi api, String name, Preferences.Visibility vis,
    String namespace
  ){
    super(api, name, vis, new TypeToken<List<E>>(){}, namespace);
  }

  public PersistedList(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends List<E>> listType,
    String namespace
  ){
    super(api, name, vis, listType, null, namespace);
  }

  public PersistedList(
    MontoyaApi api, String name, Preferences.Visibility vis,
    List<E> defaultList,
    String namespace
  ){
    super(api, name, vis, new TypeToken<List<E>>(){}, defaultList, namespace);
  }

  public PersistedList(
    MontoyaApi api, String name, Preferences.Visibility vis,
    TypeToken<? extends List<E>> listType, List<E> defaultList,
    String namespace
  ){
    super(
      api, name, vis,
      new DefaultGsonProvider(),
      listType, defaultList,
      namespace
    );
  }

  public PersistedList(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider,
    TypeToken<? extends List<E>> listType, List<E> defaultList,
    String namespace
  ){
    super(
      api, name, vis,
      new DefaultGsonProvider(), null,
      listType, defaultList,
      namespace
    );
  }

  public PersistedList(
    MontoyaApi api, String name, Preferences.Visibility vis,
    IGsonProvider gsonProvider, ILogProvider logProvider,
    TypeToken<? extends List<E>> listType, List<E> defaultList,
    String namespace
  ){
    super(
      api, name, vis,
      gsonProvider, logProvider,
      listType, defaultList,
      namespace
    );
  }

  //////////////
  // LIST API //
  //////////////
  /**
   * Inserts all of the elements in the specified collection into this
   * list at the specified position (optional operation).  Shifts the
   * element currently at that position (if any) and any subsequent
   * elements to the right (increases their indices).  The new elements
   * will appear in this list in the order that they are returned by the
   * specified collection's iterator.  The behavior of this operation is
   * undefined if the specified collection is modified while the
   * operation is in progress.  (Note that this will occur if the specified
   * collection is this list, and it's nonempty.)
   *
   * @param index index at which to insert the first element from the
   *              specified collection
   * @param c     collection containing elements to be added to this list
   * @return {@code true} if this list changed as a result of the call
   * @throws UnsupportedOperationException if the {@code addAll} operation
   *                                       is not supported by this list
   * @throws ClassCastException            if the class of an element of the specified
   *                                       collection prevents it from being added to this list
   * @throws NullPointerException          if the specified collection contains one
   *                                       or more null elements and this list does not permit null
   *                                       elements, or if the specified collection is null
   * @throws IllegalArgumentException      if some property of an element of the
   *                                       specified collection prevents it from being added to this list
   * @throws IndexOutOfBoundsException     if the index is out of range
   *                                       ({@code index < 0 || index > size()})
   */
  @Override
  public boolean addAll(int index, Collection<? extends E> c){
    boolean changed = _internalCollection.addAll(index, c);
    if(changed) save();
    return changed;
  }

  /**
   * Replaces each element of this list with the result of applying the
   * operator to that element.  Errors or runtime exceptions thrown by
   * the operator are relayed to the caller.
   *
   * @param operator the operator to apply to each element
   * @throws UnsupportedOperationException if this list is unmodifiable.
   *                                       Implementations may throw this exception if an element
   *                                       cannot be replaced or if, in general, modification is not
   *                                       supported
   * @throws NullPointerException          if the specified operator is null or
   *                                       if the operator result is a null value and this list does
   *                                       not permit null elements
   *                                       (<a href="Collection.html#optional-restrictions">optional</a>)
   * @implSpec The default implementation is equivalent to, for this {@code list}:
   * <pre>{@code
   *     final ListIterator<E> li = list.listIterator();
   *     while (li.hasNext()) {
   *         li.set(operator.apply(li.next()));
   *     }
   * }</pre>
   * <p>
   * If the list's list-iterator does not support the {@code set} operation
   * then an {@code UnsupportedOperationException} will be thrown when
   * replacing the first element.
   * @since 1.8
   */
  @Override
  public void replaceAll(UnaryOperator<E> operator){
    _internalCollection.replaceAll(operator);
    save();
  }

  /**
   * Sorts this list according to the order induced by the specified
   * {@link Comparator}.  The sort is <i>stable</i>: this method must not
   * reorder equal elements.
   *
   * <p>All elements in this list must be <i>mutually comparable</i> using the
   * specified comparator (that is, {@code c.compare(e1, e2)} must not throw
   * a {@code ClassCastException} for any elements {@code e1} and {@code e2}
   * in the list).
   *
   * <p>If the specified comparator is {@code null} then all elements in this
   * list must implement the {@link Comparable} interface and the elements'
   * {@linkplain Comparable natural ordering} should be used.
   *
   * <p>This list must be modifiable, but need not be resizable.
   *
   * @param c the {@code Comparator} used to compare list elements.
   *          A {@code null} value indicates that the elements'
   *          {@linkplain Comparable natural ordering} should be used
   * @throws ClassCastException            if the list contains elements that are not
   *                                       <i>mutually comparable</i> using the specified comparator
   * @throws UnsupportedOperationException if the list's list-iterator does
   *                                       not support the {@code set} operation
   * @throws IllegalArgumentException      (<a href="Collection.html#optional-restrictions">optional</a>)
   *                                       if the comparator is found to violate the {@link Comparator}
   *                                       contract
   * @implSpec The default implementation obtains an array containing all elements in
   * this list, sorts the array, and iterates over this list resetting each
   * element from the corresponding position in the array. (This avoids the
   * n<sup>2</sup> log(n) performance that would result from attempting
   * to sort a linked list in place.)
   * @implNote This implementation is a stable, adaptive, iterative mergesort that
   * requires far fewer than n lg(n) comparisons when the input array is
   * partially sorted, while offering the performance of a traditional
   * mergesort when the input array is randomly ordered.  If the input array
   * is nearly sorted, the implementation requires approximately n
   * comparisons.  Temporary storage requirements vary from a small constant
   * for nearly sorted input arrays to n/2 object references for randomly
   * ordered input arrays.
   *
   * <p>The implementation takes equal advantage of ascending and
   * descending order in its input array, and can take advantage of
   * ascending and descending order in different parts of the same
   * input array.  It is well-suited to merging two or more sorted arrays:
   * simply concatenate the arrays and sort the resulting array.
   *
   * <p>The implementation was adapted from Tim Peters's list sort for Python
   * (<a href="http://svn.python.org/projects/python/trunk/Objects/listsort.txt">
   * TimSort</a>).  It uses techniques from Peter McIlroy's "Optimistic
   * Sorting and Information Theoretic Complexity", in Proceedings of the
   * Fourth Annual ACM-SIAM Symposium on Discrete Algorithms, pp 467-474,
   * January 1993.
   * @since 1.8
   */
  @Override
  public void sort(Comparator<? super E> c){
    _internalCollection.sort(c);
  }

  /**
   * Returns the element at the specified position in this list.
   *
   * @param index index of the element to return
   * @return the element at the specified position in this list
   * @throws IndexOutOfBoundsException if the index is out of range
   *                                   ({@code index < 0 || index >= size()})
   */
  @Override
  public E get(int index){
    return _internalCollection.get(index);
  }

  /**
   * Replaces the element at the specified position in this list with the
   * specified element (optional operation).
   *
   * @param index   index of the element to replace
   * @param element element to be stored at the specified position
   * @return the element previously at the specified position
   * @throws UnsupportedOperationException if the {@code set} operation
   *                                       is not supported by this list
   * @throws ClassCastException            if the class of the specified element
   *                                       prevents it from being added to this list
   * @throws NullPointerException          if the specified element is null and
   *                                       this list does not permit null elements
   * @throws IllegalArgumentException      if some property of the specified
   *                                       element prevents it from being added to this list
   * @throws IndexOutOfBoundsException     if the index is out of range
   *                                       ({@code index < 0 || index >= size()})
   */
  @Override
  public E set(int index, E element){
    E prevElem =  _internalCollection.set(index, element);
    save();
    return prevElem;
  }

  /**
   * Inserts the specified element at the specified position in this list
   * (optional operation).  Shifts the element currently at that position
   * (if any) and any subsequent elements to the right (adds one to their
   * indices).
   *
   * @param index   index at which the specified element is to be inserted
   * @param element element to be inserted
   * @throws UnsupportedOperationException if the {@code add} operation
   *                                       is not supported by this list
   * @throws ClassCastException            if the class of the specified element
   *                                       prevents it from being added to this list
   * @throws NullPointerException          if the specified element is null and
   *                                       this list does not permit null elements
   * @throws IllegalArgumentException      if some property of the specified
   *                                       element prevents it from being added to this list
   * @throws IndexOutOfBoundsException     if the index is out of range
   *                                       ({@code index < 0 || index > size()})
   */
  @Override
  public void add(int index, E element){
    _internalCollection.add(index, element);
    save();
  }

  /**
   * Removes the element at the specified position in this list (optional
   * operation).  Shifts any subsequent elements to the left (subtracts one
   * from their indices).  Returns the element that was removed from the
   * list.
   *
   * @param index the index of the element to be removed
   * @return the element previously at the specified position
   * @throws UnsupportedOperationException if the {@code remove} operation
   *                                       is not supported by this list
   * @throws IndexOutOfBoundsException     if the index is out of range
   *                                       ({@code index < 0 || index >= size()})
   */
  @Override
  public E remove(int index){
    E prevElem = _internalCollection.remove(index);
    save();
    return prevElem;
  }

  /**
   * Returns the index of the first occurrence of the specified element
   * in this list, or -1 if this list does not contain the element.
   * More formally, returns the lowest index {@code i} such that
   * {@code Objects.equals(o, get(i))},
   * or -1 if there is no such index.
   *
   * @param o element to search for
   * @return the index of the first occurrence of the specified element in
   * this list, or -1 if this list does not contain the element
   * @throws ClassCastException   if the type of the specified element
   *                              is incompatible with this list
   *                              (<a href="Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException if the specified element is null and this
   *                              list does not permit null elements
   *                              (<a href="Collection.html#optional-restrictions">optional</a>)
   */
  @Override
  public int indexOf(Object o){
    return _internalCollection.indexOf(o);
  }

  /**
   * Returns the index of the last occurrence of the specified element
   * in this list, or -1 if this list does not contain the element.
   * More formally, returns the highest index {@code i} such that
   * {@code Objects.equals(o, get(i))},
   * or -1 if there is no such index.
   *
   * @param o element to search for
   * @return the index of the last occurrence of the specified element in
   * this list, or -1 if this list does not contain the element
   * @throws ClassCastException   if the type of the specified element
   *                              is incompatible with this list
   *                              (<a href="Collection.html#optional-restrictions">optional</a>)
   * @throws NullPointerException if the specified element is null and this
   *                              list does not permit null elements
   *                              (<a href="Collection.html#optional-restrictions">optional</a>)
   */
  @Override
  public int lastIndexOf(Object o){
    return _internalCollection.lastIndexOf(o);
  }

  /**
   * Returns a list iterator over the elements in this list (in proper
   * sequence).
   *
   * @return a list iterator over the elements in this list (in proper
   * sequence)
   */
  @Override
  public ListIterator<E> listIterator(){
    return _internalCollection.listIterator();
  }

  /**
   * Returns a list iterator over the elements in this list (in proper
   * sequence), starting at the specified position in the list.
   * The specified index indicates the first element that would be
   * returned by an initial call to {@link ListIterator#next next}.
   * An initial call to {@link ListIterator#previous previous} would
   * return the element with the specified index minus one.
   *
   * @param index index of the first element to be returned from the
   *              list iterator (by a call to {@link ListIterator#next next})
   * @return a list iterator over the elements in this list (in proper
   * sequence), starting at the specified position in the list
   * @throws IndexOutOfBoundsException if the index is out of range
   *                                   ({@code index < 0 || index > size()})
   */
  @Override
  public ListIterator<E> listIterator(int index){
    return _internalCollection.listIterator(index);
  }

  /**
   * Returns a view of the portion of this list between the specified
   * {@code fromIndex}, inclusive, and {@code toIndex}, exclusive.  (If
   * {@code fromIndex} and {@code toIndex} are equal, the returned list is
   * empty.)  The returned list is backed by this list, so non-structural
   * changes in the returned list are reflected in this list, and vice-versa.
   * The returned list supports all of the optional list operations supported
   * by this list.<p>
   * <p>
   * This method eliminates the need for explicit range operations (of
   * the sort that commonly exist for arrays).  Any operation that expects
   * a list can be used as a range operation by passing a subList view
   * instead of a whole list.  For example, the following idiom
   * removes a range of elements from a list:
   * <pre>{@code
   *      list.subList(from, to).clear();
   * }</pre>
   * Similar idioms may be constructed for {@code indexOf} and
   * {@code lastIndexOf}, and all of the algorithms in the
   * {@code Collections} class can be applied to a subList.<p>
   * <p>
   * The semantics of the list returned by this method become undefined if
   * the backing list (i.e., this list) is <i>structurally modified</i> in
   * any way other than via the returned list.  (Structural modifications are
   * those that change the size of this list, or otherwise perturb it in such
   * a fashion that iterations in progress may yield incorrect results.)
   *
   * @param fromIndex low endpoint (inclusive) of the subList
   * @param toIndex   high endpoint (exclusive) of the subList
   * @return a view of the specified range within this list
   * @throws IndexOutOfBoundsException for an illegal endpoint index value
   *                                   ({@code fromIndex < 0 || toIndex > size ||
   *                                   fromIndex > toIndex})
   */
  @Override
  public List<E> subList(int fromIndex, int toIndex){
    return _internalCollection.subList(fromIndex, toIndex);
  }
}
