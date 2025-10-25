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
private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
private val preferences: MutableMap<String, BurpPreference<*>> = mutableMapOf()


class PreferenceProxy<T>(
    val key: String,
    val serializer: KSerializer<in T>? = null,
    val listener: ((old: T, new: T) -> Unit)? = null
) : ReadWriteProperty<Any?, T> {
    private var _pref: BurpPreference<T>
    init {
        try {
            _pref = preferences.getOrElse(key) {
                throw RuntimeException(
                    "Cannot use com.coreyd97.montoyautilities.preference $key before it has been declared.\n" +
                            "Use 'by com.coreyd97.montoyautilities.Preference(...)' instead, or declare the com.coreyd97.montoyautilities.preference elsewhere before using 'by com.coreyd97.montoyautilities.PreferenceProxy(...)'"
                )
            } as BurpPreference<T>
            _pref.listeners.add { old, new ->
                listener?.invoke(old ?: new!!, new!!)
            }
        } catch (e: ClassCastException) {
            throw RuntimeException("com.coreyd97.montoyautilities.Preference $key was previously declared as a different type.")
        }
    }

    override fun getValue(thisRef: Any?, property: KProperty<*>): T {
        if(!_pref.initialized) {
//            throw RuntimeException("com.coreyd97.montoyautilities.Preference proxy should not load the value before the com.coreyd97.montoyautilities.preference itself! $key")
            val serializer: KSerializer<in T> = serializer ?: serializer(property.returnType)
            _pref.initValueIfNeeded(serializer)
        }
        try {
            return _pref.value ?: _pref.default as T
        } catch (e: ClassCastException) {
            throw RuntimeException("com.coreyd97.montoyautilities.Preference $key was previously declared as a different type.", e)
        }
    }

    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
        try {
            _pref.value = value
        }catch (e: ClassCastException){
            throw RuntimeException("com.coreyd97.montoyautilities.Preference $key was previously declared as a different type.", e)
        }
    }
}

//todo store com.coreyd97.montoyautilities.preferences as class
class BurpPreference<T : @Serializable Any?>(
    val key: String,
    val default: T? = null,
    val storage: StorageType,
    var serializer: KSerializer<in T>? = null
) {
    val listeners = mutableListOf<(old: T?, new: T?) -> Unit>()
    //If we don't yet have a serializer, we need to defer loading until we do.
    //This will typically be done when the return type is known from the KProperty.returnType in the delegate
    var initialized = false
    var value: T? = if(serializer != null) loadValue() else null
        set(value) {
            val old = field
            field = value
            if(initialized) listeners.forEach {
                try {
                    it.invoke(old, value)
                }catch (_: Exception){}
            }
            saveValue()
        }

    fun initValueIfNeeded(serializer: KSerializer<in T>){
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
        return deserialized as T
    }

    private fun saveValue() {
        if(!initialized || storage == StorageType.TEMP) return //Don't actually save it.
        if(serializer == null && value != null){
            throw IllegalStateException("No serializer found for com.coreyd97.montoyautilities.preference $key. Try specifying the serializer.")
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
            if(customSerializer != null && _pref.serializer == null) _pref.serializer = customSerializer
            if(listener != null) _pref.listeners.add(listener)
        }catch (e: ClassCastException){
            throw RuntimeException("com.coreyd97.montoyautilities.Preference $key was previously declared as a different type.")
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
    private val key: String,
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

inline fun <reified T : @Serializable Any?> nullablePreference(
    key: String,
    default: T? = null,
    storage: StorageType = StorageType.EXTENSION,
    noinline listener: ((old: T?, new: T?) -> Unit)? = null
): NullablePreference<T> {
    return NullablePreference(key, default, storage, serializer<T>(), listener)
}

inline fun <reified T : @Serializable Any> preference(
    key: String,
    default: T,
    storage: StorageType = StorageType.EXTENSION,
    noinline listener: ((old: T, new: T) -> Unit)? = null
): Preference<T> {
    return Preference(key, default, storage, serializer<T>(), listener)
}