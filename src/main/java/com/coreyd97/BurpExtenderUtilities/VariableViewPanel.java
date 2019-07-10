package com.coreyd97.BurpExtenderUtilities;

import javax.swing.*;
import java.awt.*;

/**
 * Created by corey on 24/08/17.
 */
public class VariableViewPanel extends JPanel {
    public enum View {HORIZONTAL, VERTICAL, TABS}
    private final Component a;
    private final String aTitle;
    private final Component b;
    private final String bTitle;
    private Preferences preferences;
    private String preferenceKey;
    private Component wrapper;
    private View view;

    public VariableViewPanel(Preferences prefs, String preferenceKey,
                             Component a, String aTitle, Component b, String bTitle,
                             View defaultView){
        this.preferences = prefs;
        this.preferenceKey = preferenceKey;

        if(this.preferences != null && this.preferenceKey != null){
            this.preferences.registerSetting(this.preferenceKey, View.class, defaultView, Preferences.Visibility.GLOBAL);
            view = (View) this.preferences.getSetting(this.preferenceKey);
        }else{
            view = defaultView;
        }

        this.a = a;
        this.aTitle = aTitle;
        this.b = b;
        this.bTitle = bTitle;
        this.setLayout(new BorderLayout());
        this.setView(view);
    }

    public VariableViewPanel(Preferences preferences, String preferenceKey,
                             Component a, String aTitle, Component b, String bTitle) {
        this(preferences, preferenceKey, a, aTitle, b, bTitle, null);
    }

    public VariableViewPanel(Component a, String aTitle, Component b, String bTitle, View defaultView){
        this(null, null, a, aTitle, b, bTitle, defaultView);
    }

    public View getView(){
        return this.view;
    }

    public void setView(View view){
        if(view == null) view = View.VERTICAL;
        switch (view){
            case HORIZONTAL:
            case VERTICAL: {
                this.wrapper = new JSplitPane();
                ((JSplitPane) wrapper).setLeftComponent(a);
                ((JSplitPane) wrapper).setRightComponent(b);
                if(view == View.HORIZONTAL){
                    ((JSplitPane) wrapper).setOrientation(JSplitPane.HORIZONTAL_SPLIT);
                }else{
                    ((JSplitPane) wrapper).setOrientation(JSplitPane.VERTICAL_SPLIT);
                }
                ((JSplitPane) wrapper).setResizeWeight(0.5);
                break;
            }
            case TABS: {
                this.wrapper = new JTabbedPane();
                ((JTabbedPane) wrapper).addTab(aTitle, a);
                ((JTabbedPane) wrapper).addTab(bTitle, b);
                break;
            }
        }
        this.removeAll();
        this.add(wrapper, BorderLayout.CENTER);
        this.revalidate();
        this.repaint();
        this.view = view;

        if(this.preferences != null && this.preferenceKey != null) {
            this.preferences.setSetting(this.preferenceKey, view);
        }
    }



}
