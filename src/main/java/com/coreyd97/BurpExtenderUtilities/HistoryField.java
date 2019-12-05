package com.coreyd97.BurpExtenderUtilities;

import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.plaf.basic.BasicComboBoxEditor;
import java.awt.*;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Stack;

/**
 * Created by corey on 05/09/17.
 */
public class HistoryField extends JComboBox {

    private static Type HISTORY_TYPE_TOKEN = new TypeToken<List<String>>(){}.getType();
    private final int maxHistory;
    private final Preferences preferences;
    private final String preferencesKey;
    private LinkedList<String> history;

    public HistoryField(final int maxHistory){
        this(null, null, maxHistory);
    }

    public HistoryField(Preferences preferences, String preferencesKey, final int maxHistory){
        this.maxHistory = maxHistory;
        this.preferences = preferences;
        this.preferencesKey = preferencesKey;
        this.history = new LinkedList<>();

        configureComponent();

        loadHistory();
    }

    private void configureComponent(){
        this.setModel(new HistoryComboModel());
        this.setEditor(new BasicComboBoxEditor(){
            JTextField editorComponent;
            @Override
            protected JTextField createEditorComponent() {
                editorComponent = new JTextField();
                editorComponent.setOpaque(false);
                return editorComponent;
            }

            @Override
            public Component getEditorComponent() {
                return editorComponent;
            }
        });
        this.setEditable(true);
        this.setOpaque(true);
    }

    private void loadHistory(){
        if(this.preferences != null && this.preferencesKey != null){
            history.clear();
            preferences.registerSetting(preferencesKey, HISTORY_TYPE_TOKEN, new ArrayList<String>(), Preferences.Visibility.GLOBAL);
            ArrayList<String> oldSearches = preferences.getSetting(preferencesKey);
            history.addAll(oldSearches);
        }
    }

    public void setForegroundColor(Color color){
        this.getEditor().getEditorComponent().setForeground(color);
    }

    public void setBackgroundColor(Color color){
        this.getEditor().getEditorComponent().setBackground(color);
    }

    public class HistoryComboModel extends DefaultComboBoxModel {

        public void addToHistory(String val){
            if(val.equals("")) return;
            history.remove(val); //Remove in case it was already in the list
            history.addFirst(val); //Add to the top of the list

            while(history.size() > maxHistory) history.removeLast();

            if(preferences != null && preferencesKey != null ){
                preferences.setSetting(preferencesKey, history);
            }
            this.fireContentsChanged(val, 0, history.size());
        }

        @Override
        public int getSize() {
            return history.size();
        }

        @Override
        public Object getElementAt(int i) {
            return history.get(i);
        }
    }
}
