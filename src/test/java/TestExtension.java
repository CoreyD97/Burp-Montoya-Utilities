import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.coreyd97.montoyautilities.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;

//Note
public class TestExtension implements BurpExtension, ILogProvider {

    private static final String extensionName = "My Extension";
    private static final String extensionTabTitle = "Extension";

    public static MontoyaApi montoya;

    //UX
    private PopOutPanel popOutPanel;
    private JPanel extensionPanel;
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

    @Override
    public void initialize(MontoyaApi api) {
        
        //Burp Specific
        montoya = api;
        montoya.extension().setName(extensionName);
        //END Burp Specific
//
//        //Firstly, we need to supply an GSON instance for the library to use.
//        //We could give our own implementation (by having a class implement iGsonProvider)
//        //But we can just use the default. We don't need to customise it.
//        this.gsonProvider = new DefaultGsonProvider();
//
//        //If you have any objects you want to supply custom serialization for,
//        //you can tell the gson provider how to serialize them like this. Gson will handle most classes without issue!
//        //Note: CustomObjectSerializer will implement JsonSerializer and/or JsonDeserializer
//
//        //this.gsonProvider.registerTypeAdapter(CustomObject.class, new CustomObjectSerializer());
//
//        //Now we have a way to serialize our preferences. We can initialize the preference store.
//        //I've made this static so we can access it in any class very easily!
//        TestExtension.preferences = new Preferences(montoya, gsonProvider, this);
//        //The logProvider parameter is optional,
//        // as an example this class implements iLogProvider and simply logs the preferences logs to stdout.
//        // or you could not supply a logProvider at all and it simply won't log preference logs.
//
//
//        //Here we register settings which will persist over the current project.
//        //registerProjectSetting(settingName, Type, defaultValue)
//        TestExtension.preferences.registerSetting("Alpha", String.class, "Project Alpha", Preferences.Visibility.PROJECT);
//        TestExtension.preferences.registerSetting("Beta", String.class, "Project Beta", Preferences.Visibility.PROJECT);
//        TestExtension.preferences.registerSetting("Charlie", String.class, "Project Charlie", Preferences.Visibility.PROJECT);
//
//        //Defining global settings works in the same way.
//        TestExtension.preferences.registerSetting("TextArea", String.class, "Hello World!", Preferences.Visibility.GLOBAL);
//        TestExtension.preferences.registerSetting("LongTest", Long.class, 0, Preferences.Visibility.GLOBAL);
//
//
//        TestExtension.preferences.registerSetting("ProjectString", String.class, "Example String 1", Preferences.Visibility.PROJECT);
//        TestExtension.preferences.registerSetting("ProjectInteger", Integer.class, 1024, Preferences.Visibility.PROJECT);
//        TestExtension.preferences.registerSetting("ProjectBoolean", Boolean.class, true, Preferences.Visibility.PROJECT);
//
//        TestExtension.preferences.registerSetting("GlobalString", String.class, "Example String 2", Preferences.Visibility.GLOBAL);
//        TestExtension.preferences.registerSetting("GlobalInteger", Integer.class, 2048, Preferences.Visibility.GLOBAL);
//        TestExtension.preferences.registerSetting("GlobalBoolean", Boolean.class, false, Preferences.Visibility.GLOBAL);
//
//        //If you have a more complex type such as an arraylist or hash map, use the format below for the type parameter.
//        //new TypeToken<YOURTYPEHERE>(){}.getType()
//        TestExtension.preferences.registerSetting("TypeTest", new TypeToken<HashMap<String, String>>(){}.getType(), new HashMap<String, String>());
//
//        //You can also create volatile preferences, which will only exist until burp is closed!
//        TestExtension.preferences.registerSetting("Volatile", String.class, "Default", Preferences.Visibility.VOLATILE);
//
//        //You want to get a value?
//        String example = TestExtension.preferences.getSetting("GlobalString");
//        //Note, this will automatically attempt to cast the value to whatever type you're saying you want.
//        //So the below will attempt to cast the value to a boolean (but will fail during runtime!)
//        //Boolean exampleWillFail = TestExtension.preferences.getSetting("GlobalString");
//        //Make sure you know what type you're requesting.
//
//
//        //This can be used to get the registered type of a setting.
//        Type examplesRegisteredType = TestExtension.preferences.getSettingType("GlobalString");
//
//
//        //Want to set a value?
//        TestExtension.preferences.setSetting("GlobalString", "A new value");
        //You do not need to worry about if the setting was registered as global/project/volatile.
        // The lib will handle it for you.

        //Now we've registered our settings. We can build the UI!
        //Create our panels as you normally would.
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                TestExtension.this.extensionPanel = buildUI();
                TestExtension.this.popOutPanel = new PopOutPanel(extensionPanel, "Extension Test");
                JMenu menu = new JMenu("Extension Test");
                menu.add(new JMenuItem(new AbstractAction("Pop In/Out") {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        popOutPanel.popOut();
                    }
                }));
                montoya.userInterface().menuBar().registerMenu(menu);
                montoya.userInterface().registerSuiteTab("Extender Utils Test", popOutPanel);
            }
        });
    }

    @Override
    public void logOutput(String message) {
        System.out.println(message);
    }

    @Override
    public void logError(String errorMessage) {
        System.err.println(errorMessage);
    }

    private JPanel buildUI(){
//        //To make it easy to build our UI, PanelBuilder can be used to generate the UI.
//
//        //Here we create our component groups.
//        //These will be used as sections to segregate different preference areas.
//        //Note: The title parameter is optional and will add a border with the title if provided
//        //These component groups are simply standard JPanels with some added preference adding methods
//        //And can be added directly to your panel. Or use the panel builder as described further on here.
//        ComponentGroup group1 = new ComponentGroup(ComponentGroup.Orientation.HORIZONTAL, "Group 1");
//        ComponentGroup group2 = new ComponentGroup(ComponentGroup.Orientation.HORIZONTAL, "Group 2");
//        ComponentGroup group3 = new ComponentGroup(ComponentGroup.Orientation.HORIZONTAL, "Group 3");
//        ComponentGroup group4 = new ComponentGroup(ComponentGroup.Orientation.HORIZONTAL, "Group 4");
//        ComponentGroup group5 = new ComponentGroup(ComponentGroup.Orientation.VERTICAL, "Group 5");
//        ComponentGroup group6 = new ComponentGroup(ComponentGroup.Orientation.HORIZONTAL, "Group 6");
//
//        //We can now add components to their panels to manage the preferences.
//        //For example, we want to add some components to "Group 5"
//        group5.addPreferenceComponent(preferences, "GlobalString","GlobalString:", false);
//        group5.addPreferenceComponent(preferences, "GlobalInteger", "GlobalInteger:", true);
//        group5.addPreferenceComponent(preferences, "GlobalBoolean", "GlobalBoolean:", true);
//
//        group1.addPreferenceComponent(preferences, "ProjectString", "ProjectString:", false);
//        group1.addPreferenceComponent(preferences, "ProjectInteger", "ProjectInteger:", false);
//        group1.addPreferenceComponent(preferences, "ProjectBoolean", "ProjectBoolean:", false);
//
//        //componentGroup.addPreferenceComponent(String preferenceName)
//        //This will automatically determine the appropriate type for our preference and add the
//        //component to the group.
//        //The preference components generated will automatically update the stored value in the preferences
//        //when the component is modified.
//        //Additionally, if you set a preference value using preferences.setSetting(setting, value)
//        //The component will also automatically update to reflect that!
//
//
//        //If we want to create a specific component for our setting. These methods also exist.
//        //JTextArea jTextArea = PanelBuilder.createPreferenceTextArea(preferences, "G2String", "Optional label for the component");
//        //JCheckBox jCheckBox = PanelBuilder.createPreferenceCheckBox(preferences, "SettingName", "Optional label for the component");
//        //JSpinner jspinner = PanelBuilder.createPreferenceSpinner(preferences, "SettingName");
//        //JTextField jTextField = PanelBuilder.createPreferenceTextField(preferences, "SettingName");
//        //JToggleButton jToggleButton = PanelBuilder.createPreferenceToggleButton(preferences, "A title for the button", "SettingName");
//
//        //These components can then be added as normal.
//
//        //When adding components to a componentgroup, the components are added in a column or row
//        //depending on orientation specified, with the last added item at the bottom/right
//        //If you wish to customise the gridbagconstraints before the component is added:
//        GridBagConstraints gbc = group5.generateNextConstraints(true);
//        gbc.fill = GridBagConstraints.NONE;
//        //etc.
//        //Then add your component as described earlier.
//        //group5.addComponent(jCheckBox, gbc);
//
//
//        //If you want to create a panel with various sized components or various placements
//        //The panelbuilder can be used to specify the layout of various components to be placed in a panel.
//        //Simply create a 2D grid and specify which of your components to place where.
//        //If a component spans multiple columns/rows, simply add its reference to both locations!
//        //See group 1 for an example of a group which spans multiple rows/columns.
//        //To have a section which is empty, simply set the cell to null.
//
//        JPanel[][] layout = new JPanel[][]{
////                new JPanel[]{group1,group1,group1, null , null },
////                new JPanel[]{group1,group1,group1, null , null },
////                new JPanel[]{ null , null ,group2,group2, null },
////                new JPanel[]{group5, null ,group3,group4, null },
////                new JPanel[]{group5, null , null , null ,group6},
//                new JPanel[]{group1, null},
//                new JPanel[]{null, group5}
//        };
//
//
//        //If you want more control over the size of individual cells in the layout, you can also provide
//        //another 2d grid of weights to be used by the panel.
//
//        int[][] weights = new int[][]{
////                new int[]{1,1,1,0,0},
////                new int[]{1,1,1,0,0},
////                new int[]{0,0,10,10,0},
////                new int[]{5,0,1,1,0},
////                new int[]{5,0,0,0,1}
//                new int[]{0,0},
//                new int[]{0,0}
//        };
//        //A weight of zero will cause the cell to auto-size.
//
//        //Then build the panel specifying the weights along with the layout.
//        //Extension.this.extensionPreferencesPanel = PanelBuilder().also { it.setComponentGrid(layout, weights, Alignment.CENTER, 1, 0);
//
//
//        //Now to actually build the panel.
//        //Use the panelbuilder and specify your layout, alignment and the x and y scales.
//        //The Alignment value will pad the panel as required to shift your panel to a specific location.
//        return PanelBuilder().also { it.setComponentGrid(layout, weights, Alignment.CENTER, 0.5, 0.5);
//
//        //If weights is null, all components will be autosized :)
//        //return PanelBuilder().also { it.setComponentGrid(layout, null, Alignment.CENTER, 0.5, 0.5);
        return null;
    }


    public static void main(String[] args) {
        try {
            Method main = Class.forName("burp.StartBurp").getMethod("main", String[].class);
            ArrayList<String> argList = new ArrayList<>(Arrays.stream(args).toList());
            argList.add("--developer-extension-class-name=" + TestExtension.class.getName());
            main.invoke(null, (Object) argList.toArray(new String[]{}));
        }catch (Exception e){
            System.err.println("Cannot start burp. Check the burp jar is correctly included in the classpath.");
            e.printStackTrace();
        }
    }
}
