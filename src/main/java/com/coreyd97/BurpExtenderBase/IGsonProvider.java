package com.coreyd97.BurpExtenderBase;

import com.google.gson.Gson;
import com.google.gson.TypeAdapter;

import java.lang.reflect.Type;

public interface IGsonProvider {
    Gson getGson();

    /**
     * Register a type adapter for the given class.
     * This defines how to de/serialize an object.
     * Required if storing custom types as preferences.
     * @param type
     * @param typeAdapter
     */
    void registerTypeAdapter(Type type, TypeAdapter typeAdapter);
}
