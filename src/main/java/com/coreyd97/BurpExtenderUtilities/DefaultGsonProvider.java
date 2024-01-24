package com.coreyd97.BurpExtenderUtilities;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapterFactory;

import java.lang.reflect.Type;

public class DefaultGsonProvider implements IGsonProvider {

    protected final GsonBuilder gsonBuilder;
    protected Gson gson;

    public DefaultGsonProvider(){
        this.gsonBuilder = new GsonBuilder();
        this.gson = this.gsonBuilder.create();
    }

    @Override
    public Gson getGson() {
        return this.gson;
    }

    @Override
    public void registerTypeAdapter(Type type, Object typeAdapter) {
        this.gsonBuilder.registerTypeAdapter(type, typeAdapter);
        this.gson = this.gsonBuilder.create();
    }

    @Override
    public void registerTypeHierarchyAdapter(Class<?> clazz, Object adapter){
        this.gsonBuilder.registerTypeHierarchyAdapter(clazz, adapter);
        this.gson = this.gsonBuilder.create();
    }

    @Override
    public void registerTypeAdapterFactory(TypeAdapterFactory factory){
        this.gsonBuilder.registerTypeAdapterFactory(factory);
        this.gson = this.gsonBuilder.create();
    }
}
