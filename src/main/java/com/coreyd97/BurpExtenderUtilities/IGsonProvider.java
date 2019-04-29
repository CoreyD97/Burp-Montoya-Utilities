package com.coreyd97.BurpExtenderUtilities;

import com.google.gson.Gson;
import com.google.gson.TypeAdapter;

import java.lang.reflect.Type;

public interface IGsonProvider {
    Gson getGson();

    /**
     * Register a type adapter for the given class.
     * This defines how to de/serialize an object.
     * Required if storing custom types as preferenceComponentMap.
     * @param type
     * @param typeAdapter
     */
    void registerTypeAdapter(Type type, Object typeAdapter);
}
