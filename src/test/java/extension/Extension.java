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

public class Extension implements ITab, IBurpExtender, IGsonProvider, ILogProvider {
    private static String extensionName = "My Extension";
    private static String extensionTabTitle = "Extension";

    public static IBurpExtenderCallbacks callbacks;
    public static Extension instance;
    private static Preferences preferences;
    private static GsonBuilder gsonBuilder;
    private static Gson gson;

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
        //Serialization Setup - Required for storing preferences.
        Extension.gsonBuilder = new GsonBuilder();
        Extension.gson = Extension.gsonBuilder.create();
        //END Serialization Setup
    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        //Burp Specific
        Extension.callbacks = callbacks;
        //END Burp Specific

        //Extension Required
        Extension.instance = this;
        callbacks.setExtensionName(extensionName);
        Extension.preferences = new Preferences("PreferenceTest", this, this, callbacks);
        //END Extension Required

        try {
            Extension.preferences.addProjectSetting("Alpha", String.class, "Project Alpha");
            Extension.preferences.addProjectSetting("Beta", String.class, "Project Beta");
            Extension.preferences.addProjectSetting("Charlie", String.class, "Project Charlie");
        }catch (Exception e){
            e.printStackTrace();
        }

        //Define Settings Here
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

        Extension.preferences.addGlobalSetting("TypeTest", new TypeToken<HashMap<String, String>>(){}.getType(), new HashMap<String, String>());

        Object test = Extension.preferences.getSetting("TypeTest");
        //END Setting Definition

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
                //Create our panels
		        Extension.this.extensionTabbedPanel = new JTabbedPane();
                Extension.this.extensionMainPanel = new JPanel();

                PanelBuilder panelBuilder = new PanelBuilder(preferences);
                ComponentGroup group1 = panelBuilder.createComponentGroup("Group 1");
                ComponentGroup group2 = panelBuilder.createComponentGroup("Group 2");
                group2.addComponent(panelBuilder.createPreferenceTextArea("TextArea"));
                ComponentGroup group3 = panelBuilder.createComponentGroup("Group 3");
                ComponentGroup group4 = panelBuilder.createComponentGroup("Group 4");
                ComponentGroup group5 = panelBuilder.createComponentGroup("Group 5");
                ComponentGroup group6 = panelBuilder.createComponentGroup("Group 6");

                group5.addPreferenceComponent("Alpha");
                group5.addPreferenceComponent("Beta");
                group5.addPreferenceComponent("Charlie");

                JPanel[][] layout = new JPanel[][]{
                        new JPanel[]{group1,group1,group1, null , null },
                        new JPanel[]{group1,group1,group1, null , null },
                        new JPanel[]{ null , null ,group2,group2, null },
                        new JPanel[]{group5, null ,group3,group4, null },
                        new JPanel[]{group5, null , null , null ,group6},
                };


                try {
                    Extension.this.extensionPreferencesPanel = panelBuilder.build(layout, Alignment.CENTER, 1, 0);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                Extension.this.extensionTabbedPanel.addTab("Content", Extension.this.extensionMainPanel);
		        Extension.this.extensionTabbedPanel.addTab("Preferences", new JScrollPane(Extension.this.extensionPreferencesPanel));

                //Uncomment to add menu item to Burp's frame menu.
                /*JFrame rootFrame = (JFrame) SwingUtilities.getWindowAncestor(Extension.this.extensionTabbedPanel);
                try{
                    JMenuBar menuBar = rootFrame.getJMenuBar();
                    JMenu extensionMenu = new JMenu();
                    JMenuItem menuItem = new JMenuItem("Title");
                    menuItem.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            //Do something
                        }
                    });
                    extensionMenu.add(menuItem);
                    menuBar.add(extensionMenu, menuBar.getMenuCount() - 1);
                }catch (NullPointerException nPException){
                    //Handle exception if menu failed to add.
                }*/

                //Burp Specific
                callbacks.addSuiteTab(Extension.this);
                //END Burp Specific
            }
        });
    }


    public void registerTypeAdapter(Type type, Object typeAdapter){
        Extension.gsonBuilder.registerTypeAdapter(type, typeAdapter);
        Extension.gson = Extension.gsonBuilder.create();
    }

    public Gson getGson(){
        return Extension.gson;
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static Extension getInstance() {
        return instance;
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
