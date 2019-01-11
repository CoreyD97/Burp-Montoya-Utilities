package extension;

import burp.*;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Type;

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
        Extension.preferences.addSetting("G1String", String.class, "Example String 1");
        Extension.preferences.addSetting("G1Integer", Integer.class, 1024);
        Extension.preferences.addSetting("G1Boolean", Boolean.class, true);

        Extension.preferences.addSetting("G2String", String.class, "Example String 2");
        Extension.preferences.addSetting("G2Integer", Integer.class, 2048);
        Extension.preferences.addSetting("G2Boolean", Boolean.class, false);
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

//                PanelBuilder panelBuilder = new PanelBuilder(preferences);
//                PanelBuilder.ComponentGroup group1 = panelBuilder.createComponentGroup("Group 1");
//                group1.addSetting("G1String");
//                group1.addSetting("G1Integer");
//                group1.addSetting("G1Boolean");
//                PanelBuilder.ComponentGroup group2 = panelBuilder.createComponentGroup("Group 2");
//                group2.addSetting("G2String");
//                group2.addSetting("G2Integer");
//                group2.addSetting("G2Boolean");



                PanelBuilder panelBuilder = new PanelBuilder(preferences);
                PanelBuilder.ComponentGroup group1 = panelBuilder.createComponentGroup("Group 1");
                PanelBuilder.ComponentGroup group2 = panelBuilder.createComponentGroup("Group 2");
                PanelBuilder.ComponentGroup group3 = panelBuilder.createComponentGroup("Group 3");
                PanelBuilder.ComponentGroup group4 = panelBuilder.createComponentGroup("Group 4");
                PanelBuilder.ComponentGroup group5 = panelBuilder.createComponentGroup("Group 5");
                PanelBuilder.ComponentGroup group6 = panelBuilder.createComponentGroup("Group 6");

                JPanel[][] layout = new JPanel[][]{
                        new JPanel[]{group1,group1,group1, null , null },
                        new JPanel[]{group1,group1,group1, null , null },
                        new JPanel[]{ null , null ,group2,group2, null },
                        new JPanel[]{group5, null ,group3,group4, null },
                        new JPanel[]{group5, null , null , null ,group6},
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
