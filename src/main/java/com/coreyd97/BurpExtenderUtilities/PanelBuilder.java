package com.coreyd97.BurpExtenderUtilities;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Set;

public class PanelBuilder {

    private final Preferences preferences;
    private Set<ComponentGroup> componentGroups;

    public PanelBuilder(){
        this(null);
    }

    public PanelBuilder(Preferences preferences){
        this.preferences = preferences;
        this.componentGroups = new LinkedHashSet<>();
    }

    public ComponentGroup createComponentGroup(String title){
        ComponentGroup componentGroup = new ComponentGroup(this, title);
        this.componentGroups.add(componentGroup);
        return componentGroup;
    }

    Preferences getPreferences() {
        return preferences;
    }

    public JButton createButton(String title, ActionListener actionListener){
        JButton button = new JButton(title);
        if(actionListener != null)
            button.addActionListener(actionListener);
        return button;
    }

    public JToggleButton createToggleButton(String title, ActionListener actionListener) {
        JToggleButton button = new JToggleButton(title);
        if(actionListener != null)
            button.addActionListener(actionListener);
        return button;
    }

    public JToggleButton createPreferenceToggleButton(String title, String preferenceKey){
        throwExceptionIfNoPreferences();
        JToggleButton toggleButton = createToggleButton(title, e -> {
            this.preferences.setSetting(preferenceKey, ((JToggleButton) e.getSource()).isSelected());
        });

        boolean isSelected = this.preferences.getSetting(preferenceKey);
        toggleButton.setSelected(isSelected);
        return toggleButton;
    }
    
    public JTextField createPreferenceTextField(String preferenceKey){
        throwExceptionIfNoPreferences();
        final JTextField textComponent = new JTextField();
        String defaultValue = this.preferences.getSetting(preferenceKey);
        textComponent.setText(defaultValue);
        textComponent.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent documentEvent) {
                preferences.setSetting(preferenceKey, textComponent.getText(), false);
            }

            @Override
            public void removeUpdate(DocumentEvent documentEvent) {
                preferences.setSetting(preferenceKey, textComponent.getText(), false);
            }

            @Override
            public void changedUpdate(DocumentEvent documentEvent) {
                preferences.setSetting(preferenceKey, textComponent.getText(), false);
            }
        });

        preferences.addSettingListener((changedpreferenceKey, newValue) -> {
            if(changedpreferenceKey.equals(preferenceKey)){
                textComponent.setText((String) newValue);
            }
        });

        return textComponent;
    }

    public JSpinner createPreferenceSpinner(String preferenceKey){
        throwExceptionIfNoPreferences();
        final JSpinner spinnerComponent = new JSpinner();
        Number value = this.preferences.getSetting(preferenceKey);
        spinnerComponent.setValue(value);
        spinnerComponent.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent changeEvent) {
                preferences.setSetting(preferenceKey, spinnerComponent.getValue(), false);
            }
        });

        preferences.addSettingListener((changedSettingName, newValue) -> {
            if(changedSettingName.equals(preferenceKey)){
                spinnerComponent.setValue(newValue);
            }
        });

        return spinnerComponent;
    }

    public JCheckBox createPreferenceCheckBox(String preferenceKey, String label){
        throwExceptionIfNoPreferences();
        final JCheckBox checkComponent = new JCheckBox(label);
        Boolean value = (Boolean) this.preferences.getSetting(preferenceKey);
        checkComponent.setSelected(value);
        checkComponent.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                preferences.setSetting(preferenceKey, checkComponent.isSelected(), false);
            }
        });

        preferences.addSettingListener((changedSettingName, newValue) -> {
            if(changedSettingName.equals(preferenceKey)){
                checkComponent.setSelected((boolean) newValue);
            }
        });

        return checkComponent;
    }

    public JTextArea createPreferenceTextArea(String settingName){
        throwExceptionIfNoPreferences();
        String value = preferences.getSetting(settingName);

        JTextArea textArea = new JTextArea();
        textArea.setText(value);

        textArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent documentEvent) { saveChanges(); }
            @Override
            public void removeUpdate(DocumentEvent documentEvent) { saveChanges(); }
            @Override
            public void changedUpdate(DocumentEvent documentEvent) { saveChanges(); }

            private void saveChanges(){
                preferences.setSetting(settingName, textArea.getText(), false);
            }
        });

        return textArea;
    }

    public JPanel build(Component singleComponent, Alignment alignment, double scaleX, double scaleY){
        return build(
                new Component[][]{new Component[]{singleComponent}},
                new int[][]{new int[]{1}},
                alignment, scaleX, scaleY);
    }

    public JPanel build(Component[][] viewGrid, Alignment alignment, double scaleX, double scaleY) {
        return build(viewGrid, null, alignment, scaleX, scaleY);
    }

    public JPanel build(Component[][] viewGrid, int[][] gridWeights, Alignment alignment, double scaleX, double scaleY) {
        if(scaleX > 1 || scaleX < 0) throw new IllegalArgumentException("Scale must be between 0 and 1");
        if(scaleY > 1 || scaleY < 0) throw new IllegalArgumentException("Scale must be between 0 and 1");
        JPanel containerPanel = new JPanel(new GridBagLayout());
        HashMap<Component, GridBagConstraints> constraintsMap = new HashMap<>();
        int minx = Integer.MAX_VALUE, miny = Integer.MAX_VALUE, maxx = Integer.MIN_VALUE, maxy = Integer.MIN_VALUE;

        for (int row = 0; row < viewGrid.length; row++) {
            for (int column = 0; column < viewGrid[row].length; column++) {
                Component panel = viewGrid[row][column];
                if(panel != null) {
                    int gridx = column + 1;
                    int gridy = row + 1;

                    if (constraintsMap.containsKey(panel)) {
                        GridBagConstraints constraints = constraintsMap.get(panel);
                        if (gridx < constraints.gridx || (constraints.gridx + constraints.gridwidth) < gridx) {
                            throw new RuntimeException("Panels must be contiguous.");
                        }
                        if (gridy < constraints.gridy || (constraints.gridy + constraints.gridheight) < gridy) {
                            throw new RuntimeException("Panels must be contiguous.");
                        }

                        constraints.gridwidth = gridx - constraints.gridx + 1;
                        constraints.gridheight = gridy - constraints.gridy + 1;
                        int weight;
                        try{
                            weight = gridWeights[gridy-1][gridx-1];
                        }catch (Exception e){ weight = 0; }
                        constraints.weightx += weight;
                        constraints.weighty += weight;

                    } else {
                        GridBagConstraints constraints = new GridBagConstraints();
                        constraints.fill = GridBagConstraints.BOTH;
                        constraints.gridx = gridx;
                        constraints.gridy = gridy;
                        int weight;
                        try{
                            weight = gridWeights[gridy-1][gridx-1];
                        }catch (Exception e){ weight = 0; }
                        constraints.weightx = constraints.weighty = weight;
                        constraintsMap.put(panel, constraints);
                    }

                    if (gridx < minx) minx = gridx;
                    if (gridx > maxx) maxx = gridx;
                    if (gridy < miny) miny = gridy;
                    if (gridy > maxy) maxy = gridy;
                }else{
                    GridBagConstraints constraints = new GridBagConstraints();
                    constraints.gridx = column+1;
                    constraints.gridy = row+1;
                    constraints.fill = GridBagConstraints.BOTH;
                    constraints.weightx = constraints.weighty = 1;
                    JPanel filler = new JPanel();
                    constraintsMap.put(filler, constraints);
                }
            }
        }

        GridBagConstraints innerPanelGbc = new GridBagConstraints();
        innerPanelGbc.fill = GridBagConstraints.BOTH;
        innerPanelGbc.gridx = innerPanelGbc.gridy = 2;
        innerPanelGbc.weightx = scaleX;
        innerPanelGbc.weighty = scaleY;
        GridBagConstraints paddingLeftGbc = new GridBagConstraints();
        GridBagConstraints paddingRightGbc = new GridBagConstraints();
        GridBagConstraints paddingTopGbc = new GridBagConstraints();
        GridBagConstraints paddingBottomGbc = new GridBagConstraints();
        paddingLeftGbc.fill = paddingRightGbc.fill = paddingTopGbc.fill = paddingBottomGbc.fill = GridBagConstraints.BOTH;
        paddingLeftGbc.weightx = paddingRightGbc.weightx = (1-scaleX)/2;
        paddingTopGbc.weighty = paddingBottomGbc.weighty = (1-scaleY)/2;
        paddingLeftGbc.gridy = paddingRightGbc.gridy = 2;
        paddingTopGbc.gridx = paddingBottomGbc.gridx = 2;
        paddingLeftGbc.gridx = 1;
        paddingRightGbc.gridx = 3;
        paddingTopGbc.gridy = 1;
        paddingBottomGbc.gridy = 3;

        JPanel topPanel, leftPanel, bottomPanel, rightPanel;

        if(alignment != Alignment.FILL && alignment != Alignment.TOPLEFT
                && alignment != Alignment.TOPMIDDLE && alignment != Alignment.TOPRIGHT){
            containerPanel.add(topPanel = new JPanel(), paddingTopGbc);
//            topPanel.setBorder(BorderFactory.createLineBorder(Color.BLUE));
        }

        if(alignment != Alignment.FILL && alignment != Alignment.TOPLEFT
                && alignment != Alignment.MIDDLELEFT && alignment != Alignment.BOTTOMLEFT){
            containerPanel.add(leftPanel = new JPanel(), paddingLeftGbc);
//            leftPanel.setBorder(BorderFactory.createLineBorder(Color.BLUE));
        }

        if(alignment != Alignment.FILL && alignment != Alignment.TOPRIGHT
                && alignment != Alignment.MIDDLERIGHT && alignment != Alignment.BOTTOMRIGHT){
            containerPanel.add(rightPanel = new JPanel(), paddingRightGbc);
//            rightPanel.setBorder(BorderFactory.createLineBorder(Color.BLUE));
        }

        if(alignment != Alignment.FILL && alignment != Alignment.BOTTOMLEFT
                && alignment != Alignment.BOTTOMMIDDLE && alignment != Alignment.BOTTOMRIGHT){
            containerPanel.add(bottomPanel = new JPanel(), paddingBottomGbc);
//            bottomPanel.setBorder(BorderFactory.createLineBorder(Color.ORANGE));
        }


        JPanel innerContainer = new JPanel(new GridBagLayout());
        for (Component component : constraintsMap.keySet()) {
            innerContainer.add(component, constraintsMap.get(component));
        }
        containerPanel.add(innerContainer, innerPanelGbc);

        return containerPanel;
    }

    public JPanel build(){
        JPanel containerPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridy = gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        for (ComponentGroup componentGroup : this.componentGroups) {
            containerPanel.add(componentGroup, gbc);
            gbc.gridy++;
        }

        gbc.weighty = gbc.weightx = 100;
        containerPanel.add(new JPanel(), gbc);

        return containerPanel;
    }

    private void throwExceptionIfNoPreferences(){
        if(this.preferences == null){
            throw new IllegalStateException("Method unavailable. No preference context defined.");
        }
    }
}
