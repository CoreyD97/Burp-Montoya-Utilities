package extension;

import burp.IBurpExtenderCallbacks;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.Gson;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.util.HashMap;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;


/**
 * Please ignore my terrible JUnit/Mockito skills.
 */
public class PreferencesTest {

    private static HashMap<String, String> prefs;
    private static IBurpExtenderCallbacks callbacks;
    Preferences preferences;
    private static Extension extension;

    @BeforeClass
    public static void beforeClass() throws Exception {
        extension = new Extension();
        callbacks = Mockito.mock(IBurpExtenderCallbacks.class);
        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                prefs.put((String) invocationOnMock.getArgument(0), (String) invocationOnMock.getArgument(1));
                return null;
            }
        }).when(callbacks).saveExtensionSetting(anyString(), anyString());

        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                return prefs.get(invocationOnMock.getArgument(0));
            }
        }).when(callbacks).loadExtensionSetting(anyString());
    }

    @Before
    public void setUp() throws Exception {
        prefs = new HashMap<>();
        preferences = new Preferences("Preference Test", new DefaultGsonProvider(), callbacks);
    }

    @Test
    public void addNewSetting() throws Exception {
        //New setting with no value yet.
        preferences.registerSetting("test", String.class, Preferences.Visibility.GLOBAL);
        assertEquals(String.class, preferences.getSettingType("test"));
        assertNull(preferences.getSetting("test"));
        assertNull(callbacks.loadExtensionSetting("test"));
    }

    @Test
    public void addNewSettingWithDefault() throws Exception {
        preferences.registerSetting("test", String.class, "Hello World!", Preferences.Visibility.GLOBAL);
        assertEquals(String.class, preferences.getSettingType("test"));
        assertEquals("Hello World!", preferences.getSetting("test"));
        assertEquals(new Gson().toJson("Hello World!"), callbacks.loadExtensionSetting("test"));
    }

    @Test
    public void setSetting() throws Exception {
        preferences.registerSetting("test", String.class, Preferences.Visibility.GLOBAL);
        assertNull(preferences.getSetting("test"));
        assertEquals(String.class, preferences.getSettingType("test"));
        preferences.setSetting("test", "New Value");
        assertEquals("New Value", preferences.getSetting("test"));
        assertEquals(String.class, preferences.getSettingType("test"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetSettingWithIncorrectType() throws Exception {
        preferences.registerSetting("test", String.class, Preferences.Visibility.GLOBAL);
        preferences.setSetting("test", 1);
    }

}