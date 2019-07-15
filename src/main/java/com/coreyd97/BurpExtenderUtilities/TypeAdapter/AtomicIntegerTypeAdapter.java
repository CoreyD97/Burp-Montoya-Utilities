package com.coreyd97.BurpExtenderUtilities.TypeAdapter;

import com.google.gson.*;

import java.lang.reflect.Type;
import java.util.concurrent.atomic.AtomicInteger;

public class AtomicIntegerTypeAdapter
        implements JsonSerializer<AtomicInteger>, JsonDeserializer<AtomicInteger> {
    @Override public JsonElement serialize(AtomicInteger src, Type typeOfSrc, JsonSerializationContext context) {
        return new JsonPrimitive(src.incrementAndGet());
    }

    @Override public AtomicInteger deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
            throws JsonParseException {
        int intValue = json.getAsInt();
        return new AtomicInteger(--intValue);
    }
}
