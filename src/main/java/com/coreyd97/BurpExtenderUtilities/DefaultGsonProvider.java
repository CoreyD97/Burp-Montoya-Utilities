package com.coreyd97.BurpExtenderUtilities;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;

import java.lang.reflect.Type;

public class DefaultGsonProvider implements IGsonProvider {

    private GsonBuilder gsonBuilder;
    private Gson gson;

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
}
