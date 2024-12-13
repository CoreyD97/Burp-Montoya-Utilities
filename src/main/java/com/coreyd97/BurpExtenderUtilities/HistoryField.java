package com.coreyd97.BurpExtenderUtilities;

import com.google.gson.reflect.TypeToken;

import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import javax.swing.*;
import javax.swing.plaf.basic.BasicComboBoxEditor;
import javax.swing.undo.UndoManager;
import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Stack;

/**
 * Created by corey on 05/09/17.
 */
public class HistoryField extends JComboBox<String> {

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

        this.putClientProperty("JComboBox.isTableCellEditor", Boolean.TRUE);
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
                UndoManager undoManager = new UndoManager();
                editorComponent.getDocument().addUndoableEditListener(undoManager);
                editorComponent.addKeyListener(new KeyAdapter() {
                    @Override
                    public void keyReleased(KeyEvent e) {
                        if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                            setSelectedItem(editorComponent.getText());
                        }
                        if(e.getKeyCode() == KeyEvent.VK_ESCAPE)
                            setSelectedItem(null);
                    }
                });
                getActionMap().put("Undo", new AbstractAction("Undo") {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (undoManager.canUndo()) undoManager.undo();
                    }
                });

                getActionMap().put("Redo", new AbstractAction("Redo") {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (undoManager.canUndo()) undoManager.redo();
                    }
                });

                getInputMap().put(KeyStroke.getKeyStroke("control Z"), "Undo");
                getInputMap().put(KeyStroke.getKeyStroke("control Y"), "Redo");

                return editorComponent;
            }

            @Override
            public Component getEditorComponent() {
                return editorComponent;
            }
        });
        this.addItemListener(e -> {
            if(e.getStateChange() == ItemEvent.SELECTED){
                String selectedItem = (String)this.getSelectedItem();
                ((HistoryComboModel)getModel()).addToHistory(selectedItem);
            }
        });
        this.setEditable(true);
        this.setOpaque(true);
    }

    private void loadHistory(){
        if(this.preferences != null && this.preferencesKey != null){
            history.clear();
            preferences.register(preferencesKey, HISTORY_TYPE_TOKEN, new ArrayList<String>(), Preferences.Visibility.GLOBAL);
            ArrayList<String> oldSearches = preferences.get(preferencesKey);
            history.addAll(oldSearches);
        }
    }

    public void setForegroundColor(Color color){
        this.getEditor().getEditorComponent().setForeground(color);
    }

    public void setBackgroundColor(Color color){
        this.getEditor().getEditorComponent().setBackground(color);
    }

    public class HistoryComboModel extends DefaultComboBoxModel<String> {

        public void addToHistory(String val){
            if(val.equals("")) return;
            history.remove(val); //Remove in case it was already in the list
            history.addFirst(val); //Add to the top of the list

            while(history.size() > maxHistory) history.removeLast();

            if(preferences != null && preferencesKey != null ){
                preferences.set(preferencesKey, history);
            }
            this.fireContentsChanged(val, 0, history.size());
        }

        @Override
        public int getSize() {
            return history.size();
        }

        @Override
        public String getElementAt(int i) {
            return history.get(i);
        }
    }
}
