package com.coreyd97.BurpExtenderUtilities.nameManager;

import java.util.HashSet;
import java.util.Set;

public class NameManager{
  public static void reserve(String newName){
    if(!_nameSet.add(newName))
      throw new NameCollisionException("Name " + newName + " is already reserved.");
  }

  public static void release(String name){
    //this might not actually need to throw an exception... it may not be useful... not sure
    if(!_nameSet.remove(name))
      throw new KeyNotReservedException("Name " + name + " was not previously reserved.");
  }

  public static boolean isReserved(String name){ return _nameSet.contains(name); }

  private static final Set<String> _nameSet = new HashSet<>();
}
