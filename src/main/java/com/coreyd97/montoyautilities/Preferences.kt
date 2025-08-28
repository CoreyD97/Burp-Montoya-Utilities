package com.coreyd97.montoyautilities

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.persistence.Preferences
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty
import kotlin.reflect.KType

enum class StorageType { PROJECT, EXTENSION, TEMP }

private val montoya: MontoyaApi = MontoyaUtilities.montoya
private val preferenceData: Preferences = montoya.persistence().preferences()
private val projectData: PersistedObject = montoya.persistence().extensionData()
private val json = Json { ignoreUnknownKeys = true }
private val preferences: MutableMap<String, BurpPreference<*>> = mutableMapOf()


class PreferenceProxy<T>(
    val key: String,
    val listener: ((old: T, new: T) -> Unit)? = null
) : ReadWriteProperty<Any?, T> {
    private var _pref: BurpPreference<T>
    init {
        try {
            _pref = preferences.getOrElse(key) {
                throw RuntimeException(
                    "Cannot use preference $key before it has been declared.\n" +
                            "Use 'by Preference(...)' instead, or declare the preference elsewhere before using 'by PreferenceProxy(...)'"
                )
            } as BurpPreference<T>
            _pref.listeners.add { old, new ->
                listener?.invoke(old ?: new!!, new!!)
            }
        } catch (e: ClassCastException) {
            throw RuntimeException("Preference $key was previously declared as a different type.")
        }
    }

    override fun getValue(thisRef: Any?, property: KProperty<*>): T {
        if(!_pref.initialized)
            _pref.initValueIfNeeded(serializer(property.returnType) as KSerializer<T>)
        try {
            return preferences[key]!!.value as T
        } catch (e: ClassCastException) {
            throw RuntimeException("Preference $key was previously declared as a different type.", e)
        }
    }

    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
        try {
            val pref = preferences[key] as BurpPreference<T>
            pref.value = value
        }catch (e: ClassCastException){
            throw RuntimeException("Preference $key was previously declared as a different type.", e)
        }
    }
}

//todo store preferences as class
class BurpPreference<T : @Serializable Any?>(
    val key: String,
    val default: T? = null,
    val storage: StorageType,
    var serializer: KSerializer<T>? = null
) {
    val listeners = mutableListOf<(old: T?, new: T?) -> Unit>()
    //If we don't yet have a serializer, we need to defer loading until we do.
    //This will typically be done when the return type is known from the KProperty.returnType in the delegate
    var initialized = false
    var value: T? = if(serializer != null) loadValue() else null
        set(value) {
            val old = field
            field = value
            if(initialized) listeners.forEach { it.invoke(old, value) }
            saveValue()
        }

    fun initValueIfNeeded(serializer: KSerializer<T>){
        if(initialized) return
        this.serializer = serializer
        value = loadValue()
    }

    init {
        montoya.extension().registerUnloadingHandler {
            saveValue()
        }
    }

    private fun loadValue(): T? {
        val (exists, value) = when (storage) {
            StorageType.EXTENSION -> {
                Pair(preferenceData.stringKeys().contains(key), preferenceData.getString(key))
            }

            StorageType.PROJECT -> {
                Pair(projectData.stringKeys().contains(key), projectData.getString(key))
            }

            StorageType.TEMP -> {
                Pair(false, null)
            }
        }


        val deserialized = if (exists) {
            json.decodeFromString(serializer!!, value!!)
        } else {
            default
        }

        initialized = true
        return deserialized
    }

    private fun saveValue() {
        if(storage == StorageType.TEMP) return //Don't actually save it.
        if(serializer == null){
            throw IllegalStateException("No serializer found for preference $key. Try specifying the serializer.")
        }
        if(value == null){
            if (storage == StorageType.EXTENSION)
                preferenceData.deleteString(this.key)
            else
                projectData.deleteString(this.key)
        }else{
            val encoded = json.encodeToString(serializer!!, value!!)
            if (storage == StorageType.EXTENSION)
                preferenceData.setString(this.key, encoded)
            else
                projectData.setString(this.key, encoded)
        }
    }
}

open class NullablePreference<T : @Serializable Any?>(
    key: String,
    default: T? = null,
    storage: StorageType = StorageType.EXTENSION,
    customSerializer: KSerializer<in T>? = null,
    listener: ((old: T?, new: T?) -> Unit)? = null
) : ReadWriteProperty<Any?, T?> {
    protected var _pref: BurpPreference<T>

    init {
        try {
            _pref = preferences.getOrPut(key) {
                BurpPreference(key, default, storage, customSerializer)
            } as BurpPreference<T>
            if(listener != null) _pref.listeners.add(listener)
        }catch (e: ClassCastException){
            throw RuntimeException("Preference $key was previously declared as a different type.")
        }
    }

    override operator fun getValue(thisRef: Any?, property: KProperty<*>): T? {
        tryInitSerializerIfNeeded(property.returnType)
        return _pref.value
    }

    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T?) {
        tryInitSerializerIfNeeded(property.returnType)
        _pref.value = value
    }

    private fun tryInitSerializerIfNeeded(type: KType){
        if(_pref.initialized) return
        try {
            _pref.initValueIfNeeded(serializer(type) as KSerializer<T>)
        }catch (ex: SerializationException){
            //Don't try to initialize again...
            _pref.initialized = true
        }
    }
}

open class Preference<T : @Serializable Any>(
    key: String,
    val default: T,
    storage: StorageType = StorageType.EXTENSION,
    serializer: KSerializer<in T>? = null,
    listener: ((old: T, new: T) -> Unit)? = null
) : NullablePreference<T>(key, default, storage, serializer, null) {

    init {
        //The listener
        _pref.listeners.add { old, new ->
            listener?.invoke(old ?: default, new ?: default)
        }
    }

    override operator fun getValue(thisRef: Any?, property: KProperty<*>): T {
        return super.getValue(thisRef, property) ?: default
    }
}