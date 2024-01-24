package com.coreyd97.BurpExtenderUtilities;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;

public class GsonUtilities{
  public static <T> T clone(T src, Type type, Gson gson){
    String jsonDefaultValue = gson.toJson(src);
    return gson.fromJson(jsonDefaultValue, type);
  }
}
