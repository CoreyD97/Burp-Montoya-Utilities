package extension;

import burp.*;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Type;
import java.util.HashMap;

public class Extension implements ITab, IBurpExtender, IGsonProvider{
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
        Extension.preferences = new Preferences(this, callbacks);
        //END Extension Required

        //Define Settings Here
        Extension.preferences.addSetting("TextArea", String.class, "Hello World!");

        Extension.preferences.addSetting(PREF_RESTRICT_TO_SCOPE, Boolean.class, false);
        Extension.preferences.addSetting(PREF_LOG_GLOBAL, Boolean.class, true);
        Extension.preferences.addSetting(PREF_LOG_PROXY, Boolean.class, true);
        Extension.preferences.addSetting(PREF_LOG_SPIDER, Boolean.class, true);
        Extension.preferences.addSetting(PREF_LOG_INTRUDER, Boolean.class, true);
        Extension.preferences.addSetting(PREF_LOG_SCANNER, Boolean.class, true);
        Extension.preferences.addSetting(PREF_LOG_REPEATER, Boolean.class, true);
        Extension.preferences.addSetting(PREF_LOG_SEQUENCER, Boolean.class, true);
        Extension.preferences.addSetting(PREF_LOG_EXTENDER, Boolean.class, true);
        Extension.preferences.addSetting(PREF_LOG_TARGET_TAB, Boolean.class, true);

        Extension.preferences.addSetting("G1String", String.class, "Example String 1");
        Extension.preferences.addSetting("G1Integer", Integer.class, 1024);
        Extension.preferences.addSetting("G1Boolean", Boolean.class, true);

        Extension.preferences.addSetting("G2String", String.class, "Example String 2");
        Extension.preferences.addSetting("G2Integer", Integer.class, 2048);
        Extension.preferences.addSetting("G2Boolean", Boolean.class, false);

        Extension.preferences.addSetting("TypeTest", new TypeToken<HashMap<String, String>>(){}.getType(), new HashMap<String, String>());

        Object test = Extension.preferences.getSetting("TypeTest");
        //END Setting Definition

        buildUI();
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
                PanelBuilder.ComponentGroup group1 = panelBuilder.createComponentGroup("Group 1");
                PanelBuilder.ComponentGroup group2 = panelBuilder.createComponentGroup("Group 2");
                group2.addTextAreaSetting("TextArea");
                PanelBuilder.ComponentGroup group3 = panelBuilder.createComponentGroup("Group 3");
                PanelBuilder.ComponentGroup group4 = panelBuilder.createComponentGroup("Group 4");
                PanelBuilder.ComponentGroup group5 = panelBuilder.createComponentGroup("Group 5");
                PanelBuilder.ComponentGroup group6 = panelBuilder.createComponentGroup("Group 6");

                PanelBuilder.ComponentGroup logFromPanel = panelBuilder.createComponentGroup("Log From");
                JCheckBox restrict = (JCheckBox) logFromPanel.addSetting(PREF_RESTRICT_TO_SCOPE, "In scope items only");
                restrict.setBorder(BorderFactory.createLineBorder(Color.BLUE));
                logFromPanel.addComponent((JComponent) Box.createVerticalStrut(5));
                JCheckBox logAllTools = (JCheckBox) logFromPanel.addSetting(PREF_LOG_GLOBAL, "All Tools");
                JCheckBox logSpider = (JCheckBox) logFromPanel.addSetting(PREF_LOG_SPIDER, "Spider");
                JCheckBox logIntruder = (JCheckBox) logFromPanel.addSetting(PREF_LOG_INTRUDER, "Intruder");
                JCheckBox logScanner = (JCheckBox) logFromPanel.addSetting(PREF_LOG_SCANNER, "Scanner");
                JCheckBox logRepeater = (JCheckBox) logFromPanel.addSetting(PREF_LOG_REPEATER, "Repeater");
                JCheckBox logSequencer = (JCheckBox) logFromPanel.addSetting(PREF_LOG_SEQUENCER, "Sequencer");
                JCheckBox logProxy = (JCheckBox) logFromPanel.addSetting(PREF_LOG_PROXY, "Proxy");
                JCheckBox logTarget = (JCheckBox) logFromPanel.addSetting(PREF_LOG_TARGET_TAB, "Target");
                JCheckBox logExtender = (JCheckBox) logFromPanel.addSetting(PREF_LOG_EXTENDER, "Extender");

                {   //Disable check boxes if global logging is enabled.
                    boolean globalDisabled = !logAllTools.isSelected();
                    logSpider.setEnabled(globalDisabled);
                    logIntruder.setEnabled(globalDisabled);
                    logScanner.setEnabled(globalDisabled);
                    logRepeater.setEnabled(globalDisabled);
                    logSequencer.setEnabled(globalDisabled);
                    logProxy.setEnabled(globalDisabled);
                    logTarget.setEnabled(globalDisabled);
                    logExtender.setEnabled(globalDisabled);
                }

                logAllTools.addActionListener(actionEvent -> {
                    boolean globalDisabled = !logAllTools.isSelected();
                    logSpider.setEnabled(globalDisabled);
                    logIntruder.setEnabled(globalDisabled);
                    logScanner.setEnabled(globalDisabled);
                    logRepeater.setEnabled(globalDisabled);
                    logSequencer.setEnabled(globalDisabled);
                    logProxy.setEnabled(globalDisabled);
                    logTarget.setEnabled(globalDisabled);
                    logExtender.setEnabled(globalDisabled);
                });


                JLabel statusLabel = new JLabel("Status: Not Running");
                statusLabel.setBorder(BorderFactory.createLineBorder(Color.CYAN));
                group1.addComponent(statusLabel);
                JToggleButton startStopButton = group1.addToggleButton("Start", null);

                JPanel[][] layout = new JPanel[][]{
                        new JPanel[]{group1,group1,group1, null , null },
                        new JPanel[]{group1,group1,group1, null , null },
                        new JPanel[]{ null , null ,group2,group2, null },
                        new JPanel[]{logFromPanel, null ,group3,group4, null },
                        new JPanel[]{logFromPanel, null , null , null ,group6},
                };


                try {
                    Extension.this.extensionPreferencesPanel = panelBuilder.build(layout, PanelBuilder.Alignment.CENTER);
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
