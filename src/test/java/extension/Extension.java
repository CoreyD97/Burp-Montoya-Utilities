package extension;

import burp.*;
import com.coreyd97.BurpExtenderUtilities.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;

//Note
public class Extension implements ITab, IBurpExtender, ILogProvider {
    private static String extensionName = "My Extension";
    private static String extensionTabTitle = "Extension";

    public static IBurpExtenderCallbacks callbacks;
    private static Preferences preferences;
    private DefaultGsonProvider gsonProvider;

    //UX
    private JTabbedPane extensionTabbedPanel;
    private JPanel extensionMainPanel;
    private JPanel extensionPreferencesPanel;

    public static final String PREF_RESTRICT_TO_SCOPE = "restricttoscope";
    public static final String PREF_LOG_GLOBAL = "logglobal";
    public static final String PREF_LOG_PROXY = "logproxy";
    public static final String PREF_LOG_SPIDER = "logspider";
    public static final String PREF_LOG_INTRUDER = "logintruder";
    public static final String PREF_LOG_SCANNER = "logscanner";
    public static final String PREF_LOG_REPEATER = "logrepeater";
    public static final String PREF_LOG_SEQUENCER = "logsequencer";
    public static final String PREF_LOG_EXTENDER = "logextender";
    public static final String PREF_LOG_TARGET_TAB = "logtargettab";

    public Extension(){

    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        //Burp Specific
        Extension.callbacks = callbacks;
        callbacks.setExtensionName(extensionName);
        //END Burp Specific

        //Firstly, we need to supply an GSON instance for the library to use.
        //We could give our own implementation (by having a class implement iGsonProvider)
        //But we can just use the default. We don't need to customise it.
        this.gsonProvider = new DefaultGsonProvider();

        //If you have any objects you want to supply custom serialization for,
        //you can tell the gson provider how to serialize them like this. Gson will handle most classes without issue!
        //Note: CustomObjectSerializer will implement JsonSerializer and/or JsonDeserializer

        //this.gsonProvider.registerTypeAdapter(CustomObject.class, new CustomObjectSerializer());

        //Now we have a way to serialize our preferences. We can initialize the preference store.
        //I've made this static so we can access it in any class very easily!
        Extension.preferences = new Preferences("PreferenceTest", gsonProvider, this, callbacks);
        //The logProvider parameter is optional,
        // as an example this class implements iLogProvider and simply logs the preferences logs to stdout.
        // or you could not supply a logProvider at all and it simply won't log preference logs.


        //Here we register settings which will persist over the current project.
        //addProjectSetting(settingName, Type, defaultValue)
        try {
            Extension.preferences.addProjectSetting("Alpha", String.class, "Project Alpha");
            Extension.preferences.addProjectSetting("Beta", String.class, "Project Beta");
            Extension.preferences.addProjectSetting("Charlie", String.class, "Project Charlie");
        }catch (Exception e){
            e.printStackTrace();
        }

        //Defining global settings works in the same way.
        Extension.preferences.addGlobalSetting("TextArea", String.class, "Hello World!");

        Extension.preferences.addGlobalSetting(PREF_RESTRICT_TO_SCOPE, Boolean.class, false);
        Extension.preferences.addGlobalSetting(PREF_LOG_GLOBAL, Boolean.class, true);
        Extension.preferences.addGlobalSetting(PREF_LOG_PROXY, Boolean.class, true);
        Extension.preferences.addGlobalSetting(PREF_LOG_SPIDER, Boolean.class, true);
        Extension.preferences.addGlobalSetting(PREF_LOG_INTRUDER, Boolean.class, true);
        Extension.preferences.addGlobalSetting(PREF_LOG_SCANNER, Boolean.class, true);
        Extension.preferences.addGlobalSetting(PREF_LOG_REPEATER, Boolean.class, true);
        Extension.preferences.addGlobalSetting(PREF_LOG_SEQUENCER, Boolean.class, true);
        Extension.preferences.addGlobalSetting(PREF_LOG_EXTENDER, Boolean.class, true);
        Extension.preferences.addGlobalSetting(PREF_LOG_TARGET_TAB, Boolean.class, true);

        Extension.preferences.addGlobalSetting("G1String", String.class, "Example String 1");
        Extension.preferences.addGlobalSetting("G1Integer", Integer.class, 1024);
        Extension.preferences.addGlobalSetting("G1Boolean", Boolean.class, true);

        Extension.preferences.addGlobalSetting("G2String", String.class, "Example String 2");
        Extension.preferences.addGlobalSetting("G2Integer", Integer.class, 2048);
        Extension.preferences.addGlobalSetting("G2Boolean", Boolean.class, false);

        //If you have a more complex type such as an arraylist or hash map, use the format below for the type parameter.
        //new TypeToken<YOURTYPEHERE>(){}.getType()
        Extension.preferences.addGlobalSetting("TypeTest", new TypeToken<HashMap<String, String>>(){}.getType(), new HashMap<String, String>());

        //You can also create volatile preferences, which will only exist until burp is closed!
        Extension.preferences.addVolatileSetting("Volatile", String.class, "Default");

        //You want to get a value?
        String example = Extension.preferences.getSetting("G1String");
        //Note, this will automatically attempt to cast the value to whatever type you're saying you want.
        //So the below will attempt to cast the value to a boolean (but will fail during runtime!)
        //Boolean exampleWillFail = Extension.preferences.getSetting("G1String");
        //Make sure you know what type you're requesting.


        //This can be used to get the registered type of a setting.
        Type examplesRegisteredType = Extension.preferences.getSettingType("G1String");


        //Want to set a value?
        Extension.preferences.setSetting("G1String", "A new value");
        //You do not need to worry about if the setting was registered as global/project/volatile.
        // The lib will handle it for you.

        //Now we've registered our settings. We can build the UI!
        buildUI();
    }

    @Override
    public void logOutput(String message) {
        System.out.println(message);
    }

    @Override
    public void logError(String errorMessage) {
        System.err.println(errorMessage);
    }

    private void buildUI(){
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                //Create our panels as you normally would.
		        Extension.this.extensionTabbedPanel = new JTabbedPane();
                Extension.this.extensionMainPanel = new JPanel();


                //To make it easy to build our UI, PanelBuilder can be used to generate the UI.
                PanelBuilder panelBuilder = new PanelBuilder(preferences);

                //Here we create our component groups.
                //These will be used as sections to segregate different preference areas.
                //Note: The title parameter is optional.
                // Specify null if you do not wish to have a title border on your panel.
                //These component groups are simply standard JPanels with some added features.
                //And can be added directly to your panel. Or use the panel builder as described further on here.
                ComponentGroup group1 = panelBuilder.createComponentGroup("Group 1");
                ComponentGroup group2 = panelBuilder.createComponentGroup("Group 2");
                ComponentGroup group3 = panelBuilder.createComponentGroup("Group 3");
                ComponentGroup group4 = panelBuilder.createComponentGroup("Group 4");
                ComponentGroup group5 = panelBuilder.createComponentGroup("Group 5");
                ComponentGroup group6 = panelBuilder.createComponentGroup("Group 6");

                //We can now add components to their panels to manage the preferences.
                //For example, we want to add some components to "Group 5"
                group5.addPreferenceComponent("Alpha");
                group5.addPreferenceComponent("Beta");
                group5.addPreferenceComponent("Charlie");
                //componentGroup.addPreferenceComponent(String preferenceName)
                //This will automatically determine the appropriate type for our preference and add the
                //component to the group.
                //The preference components generated will automatically update the stored value in the preferences
                //when the component is modified.
                //Additionally, if you set a preference value using preferences.setSetting(setting, value)
                //The component will also automatically update to reflect that!


                //If we want to create a specific component for our setting. These methods also exist.
                //JTextArea jTextArea = panelBuilder.createPreferenceTextArea("G2String");
                //JCheckBox jCheckBox = panelBuilder.createPreferenceCheckBox("SettingName", "A label for the component, or null!");
                //JSpinner jspinner = panelBuilder.createPreferenceSpinner("SettingName");
                //JTextField jTextField = panelBuilder.createPreferenceTextField("SettingName");
                //JToggleButton jToggleButton = panelBuilder.createPreferenceToggleButton("A title for the button", "SettingName");

                //To then add these components to a componentgroup, you would do the below:
                //group5.addComponent(jCheckBox);
                //Or if you want to specify your own gridbagconstraints
                //group5.addComponent(jCheckBox, gridbagconstraints);

                //When adding components to a componentgroup, the components are added in a column, with the last added
                //item at the bottom.
                //If you wish to customise the gridbagconstraints before the component is added:
                GridBagConstraints gbc = group5.generateNextConstraints();
                gbc.fill = GridBagConstraints.NONE;
                //etc.
                //Then add your component as described earlier.
                //group5.addComponent(jCheckBox, gbc);


                //If you want to create a panel with various sized components or various placements
                //The panelbuilder can be used to specify the layout of various components to be placed in a panel.
                //Simply create a 2D grid and specify which of your components to place where.
                //If a component spans multiple columns/rows, simply add its reference to both locations!
                //See group 1 for an example of a group which spans multiple rows/columns.
                //To have a section which is empty, simply set the cell to null.

                JPanel[][] layout = new JPanel[][]{
                        new JPanel[]{group1,group1,group1, null , null },
                        new JPanel[]{group1,group1,group1, null , null },
                        new JPanel[]{ null , null ,group2,group2, null },
                        new JPanel[]{group5, null ,group3,group4, null },
                        new JPanel[]{group5, null , null , null ,group6},
                };


                try {
                    //Now to actually build the panel.
                    //Use the panelbuilder and specify your layout, alignment and the x and y scales.
                    //The Alignment value will pad the panel as required to shift your panel to a specific location.
                    Extension.this.extensionPreferencesPanel = panelBuilder.build(layout, Alignment.CENTER, 1, 0);
                } catch (Exception e) {
                    e.printStackTrace();
                }


                //If you want more control over the size of individual cells in the layout, you can also provide
                //another 2d grid of weights to be used by the panel.

                int[][] weights = new int[][]{
                        new int[]{1,1,1,0,0},
                        new int[]{1,1,1,0,0},
                        new int[]{0,0,10,10,0},
                        new int[]{5,0,0,0,0},
                        new int[]{5,0,0,0,0}
                };
                //A weight of zero will cause the cell to auto-size.

                //Then build the panel specifying the weights along with the layout.
                //Extension.this.extensionPreferencesPanel = panelBuilder.build(layout, weights, Alignment.CENTER, 1, 0);

                Extension.this.extensionTabbedPanel.addTab("Content", Extension.this.extensionMainPanel);
		        Extension.this.extensionTabbedPanel.addTab("Preferences", new JScrollPane(Extension.this.extensionPreferencesPanel));

                callbacks.addSuiteTab(Extension.this);
            }
        });
    }


    @Override
    public String getTabCaption()
    {
        return extensionTabTitle;
    }

    @Override
    public Component getUiComponent()
    {
        return this.extensionTabbedPanel;
    }



}
