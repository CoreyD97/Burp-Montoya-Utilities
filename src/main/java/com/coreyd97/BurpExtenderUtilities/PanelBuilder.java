package com.coreyd97.BurpExtenderUtilities;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;

public class PanelBuilder {

    private final Preferences preferences;
    private Set<ComponentGroup> componentGroups;
    public enum Alignment {TOPLEFT, TOPMIDDLE, TOPRIGHT, MIDDLELEFT, CENTER, MIDDLERIGHT, BOTTOMLEFT, BOTTOMMIDDLE, BOTTOMRIGHT}

    public PanelBuilder(Preferences preferences){
        this.preferences = preferences;
        this.componentGroups = new LinkedHashSet<>();
    }

    public ComponentGroup createComponentGroup(String title){
        ComponentGroup componentGroup;
        if(title == null)
            componentGroup = new ComponentGroup();
        else
            componentGroup = new ComponentGroup(title);

        this.componentGroups.add(componentGroup);

        return componentGroup;
    }

    public JPanel build(JComponent[][] viewGrid, Alignment alignment) throws Exception {
        JPanel containerPanel = new JPanel(new GridBagLayout());
        HashMap<JComponent, GridBagConstraints> constraintsMap = new HashMap<>();
        int minx = Integer.MAX_VALUE, miny = Integer.MAX_VALUE, maxx = Integer.MIN_VALUE, maxy = Integer.MIN_VALUE;

        for (int row = 0; row < viewGrid.length; row++) {
            for (int column = 0; column < viewGrid[row].length; column++) {
                JComponent panel = viewGrid[row][column];
                if(panel != null) {
                    int gridx = column + 1;
                    int gridy = row + 1;

                    if (constraintsMap.containsKey(panel)) {
                        GridBagConstraints constraints = constraintsMap.get(panel);
                        if (gridx < constraints.gridx || (constraints.gridx + constraints.gridwidth) < gridx) {
                            throw new Exception("Panels must be contiguous.");
                        }
                        if (gridy < constraints.gridy || (constraints.gridy + constraints.gridheight) < gridy) {
                            throw new Exception("Panels must be contiguous.");
                        }

                        constraints.gridwidth = gridx - constraints.gridx + 1;
                        constraints.gridheight = gridy - constraints.gridy + 1;

                    } else {
                        GridBagConstraints constraints = new GridBagConstraints();
                        constraints.fill = GridBagConstraints.BOTH;
                        constraints.gridx = gridx;
                        constraints.gridy = gridy;
                        constraints.weightx = constraints.weighty = 1;
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
//                    filler.setBorder(BorderFactory.createLineBorder(Color.PINK));
                    containerPanel.add(filler, constraints);
                }
            }
        }

        GridBagConstraints innerPanelGbc = new GridBagConstraints();
        innerPanelGbc.fill = GridBagConstraints.BOTH;
        innerPanelGbc.gridx = innerPanelGbc.gridy = 2;
//        innerPanelGbc.weightx = innerPanelGbc.weighty = 1;
        GridBagConstraints paddingLeftGbc = new GridBagConstraints();
        GridBagConstraints paddingRightGbc = new GridBagConstraints();
        GridBagConstraints paddingTopGbc = new GridBagConstraints();
        GridBagConstraints paddingBottomGbc = new GridBagConstraints();
        paddingLeftGbc.fill = paddingRightGbc.fill = paddingTopGbc.fill = paddingBottomGbc.fill = GridBagConstraints.BOTH;
        paddingLeftGbc.weightx = paddingRightGbc.weightx = Integer.MAX_VALUE;
        paddingTopGbc.weighty = paddingBottomGbc.weighty = Integer.MAX_VALUE;
        paddingLeftGbc.gridy = paddingRightGbc.gridy = 2;
        paddingTopGbc.gridx = paddingBottomGbc.gridx = 2;
        paddingLeftGbc.gridx = 1;
        paddingRightGbc.gridx = 3;
        paddingTopGbc.gridy = 1;
        paddingBottomGbc.gridy = 3;

        JPanel topPanel, leftPanel, bottomPanel, rightPanel;

        if(alignment != Alignment.TOPLEFT && alignment != Alignment.TOPMIDDLE && alignment != Alignment.TOPRIGHT){
            containerPanel.add(topPanel = new JPanel(), paddingTopGbc);
        }

        if(alignment != Alignment.TOPLEFT && alignment != Alignment.MIDDLELEFT && alignment != Alignment.BOTTOMLEFT){
            containerPanel.add(leftPanel = new JPanel(), paddingLeftGbc);
        }

        if(alignment != Alignment.TOPRIGHT && alignment != Alignment.MIDDLERIGHT && alignment != Alignment.BOTTOMRIGHT){
            containerPanel.add(rightPanel = new JPanel(), paddingRightGbc);
        }

        if(alignment != Alignment.BOTTOMLEFT && alignment != Alignment.BOTTOMMIDDLE && alignment != Alignment.BOTTOMRIGHT){
            containerPanel.add(bottomPanel = new JPanel(), paddingBottomGbc);
        }


        JPanel innerContainer = new JPanel(new GridBagLayout());
        for (JComponent component : constraintsMap.keySet()) {
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

    public class ComponentGroup extends JPanel {
        String title;
        Map<String, JComponent> preferences;
        int currentGridY = 1;

        private ComponentGroup(String title){
            this();
            this.title = title;
            this.setBorder(BorderFactory.createTitledBorder(title));
        }

        private ComponentGroup(){
            super(new GridBagLayout());
            this.preferences = new LinkedHashMap<>();
        }

        public JButton addButton(String title, final ActionListener actionListener){
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.BOTH;
            gbc.gridx = 1;
            gbc.gridy = currentGridY;
            gbc.weightx = 1;
            gbc.gridwidth = 2;
            JButton button = addButton(title, gbc, actionListener);
            currentGridY++;

            return button;
        }

        public JButton addButton(String title, GridBagConstraints constraints, final ActionListener actionListener){
            JButton button = new JButton(title);
            if(actionListener != null)
                button.addActionListener(actionListener);
            this.add(button, constraints);
            return button;
        }

        public JToggleButton addToggleButton(String title, final ActionListener actionListener){
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.BOTH;
            gbc.gridx = 1;
            gbc.gridy = currentGridY;
            gbc.weightx = 1;
            gbc.gridwidth = 2;
            JToggleButton button = addToggleButton(title, gbc, actionListener);
            currentGridY++;

            return button;
        }

        public JToggleButton addToggleButton(String title, GridBagConstraints constraints,
                                             final ActionListener actionListener){
            JToggleButton button = new JToggleButton(title);
            if(actionListener != null)
                button.addActionListener(actionListener);

            this.add(button, constraints);
            return button;
        }

        public JComponent addSetting(final String settingName){
            return addSetting(settingName, settingName);
        }

        public JComponent addSetting(final String settingName, final String label){
//            Class clazz = PanelBuilder.this.preferences.getSettingType(settingName);
            Object value = PanelBuilder.this.preferences.getSetting(settingName);
            final JComponent component;

            if(String.class.isInstance(value)){
                final JTextField textComponent = new JTextField();
                textComponent.setText((String) value);
                textComponent.getDocument().addDocumentListener(new DocumentListener() {
                    @Override
                    public void insertUpdate(DocumentEvent documentEvent) {
                        PanelBuilder.this.preferences.setSetting(settingName, textComponent.getText());
                    }

                    @Override
                    public void removeUpdate(DocumentEvent documentEvent) {
                        PanelBuilder.this.preferences.setSetting(settingName, textComponent.getText());
                    }

                    @Override
                    public void changedUpdate(DocumentEvent documentEvent) {
                        PanelBuilder.this.preferences.setSetting(settingName, textComponent.getText());
                    }
                });

                component = textComponent;
            }else if(Integer.class.isInstance(value)){
                final JSpinner spinnerComponent = new JSpinner();
                spinnerComponent.setValue(value);
                spinnerComponent.addChangeListener(new ChangeListener() {
                    @Override
                    public void stateChanged(ChangeEvent changeEvent) {
                        PanelBuilder.this.preferences.setSetting(settingName, spinnerComponent.getValue());
                    }
                });
                component = spinnerComponent;
            }else if(Boolean.class.isInstance(value)){
                final JCheckBox checkComponent = new JCheckBox(label);
                checkComponent.setSelected((Boolean) value);
                checkComponent.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        PanelBuilder.this.preferences.setSetting(settingName, checkComponent.isSelected());
                    }
                });

                component = checkComponent;

                this.preferences.put(settingName, component);
                GridBagConstraints gbc = new GridBagConstraints();
                gbc.fill = GridBagConstraints.BOTH;
                gbc.gridx = 1;
                gbc.weightx = 1;
                gbc.gridwidth = 2;
                gbc.weighty = 1;
                gbc.gridy = currentGridY;
                this.add(this.preferences.get(settingName), gbc);
                currentGridY++;

                return component;

            }else{
                final JTextField textComponent = new JTextField();
                textComponent.setText(String.valueOf(value));
                textComponent.getDocument().addDocumentListener(new DocumentListener() {
                    @Override
                    public void insertUpdate(DocumentEvent documentEvent) {
                        PanelBuilder.this.preferences.setSetting(settingName, textComponent.getText());
                    }

                    @Override
                    public void removeUpdate(DocumentEvent documentEvent) {
                        PanelBuilder.this.preferences.setSetting(settingName, textComponent.getText());
                    }

                    @Override
                    public void changedUpdate(DocumentEvent documentEvent) {
                        PanelBuilder.this.preferences.setSetting(settingName, textComponent.getText());
                    }
                });

                component = textComponent;
            }


            this.preferences.put(settingName, component);

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.BOTH;
            gbc.gridx = 1;
//            gbc.ipadx = gbc.ipady = 5;
            gbc.weightx = 0.15;
            gbc.weighty = 1;
            gbc.gridy = currentGridY;
            this.add(new JLabel(label), gbc);
            gbc.gridx++;
            gbc.weightx = 0.85;
            this.add(this.preferences.get(settingName), gbc);
            currentGridY++;

            return component;
        }

        public JTextArea addTextAreaSetting(String settingName){
            String value = String.valueOf(PanelBuilder.this.preferences.getSetting(settingName));

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
                    PanelBuilder.this.preferences.setSetting(settingName, textArea.getText());
                }
            });

            return textArea;
        }


        /**
         * Generate the constraints for the next element in the group.
         * Useful for customising before addition.
         * @return GridBagConstraints The default constraints for the next item in the group.
         */
        public GridBagConstraints generateNextConstraints(){
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.BOTH;
            gbc.weighty = gbc.weightx = 1;
            gbc.gridwidth = 2;
            gbc.gridx = 1;
            gbc.gridy = currentGridY;
            currentGridY++;
            return gbc;
        }

        /**
         * Gets the current Y coord used for generation of the panel.
         * @return int The Y coordinate.
         */
        public int getGridY(){
            return this.currentGridY;
        }


        /**
         * Sets the Y coord used for generation of the panel.
         */
        public void setGridY(int y){
            this.currentGridY = y;
        }

        public JComponent addComponent(JComponent jComponent){
            this.add(jComponent, generateNextConstraints());
            return jComponent;
        }

        public JComponent addComponent(JComponent jComponent, GridBagConstraints gridBagConstraints){
            this.add(jComponent, gridBagConstraints);
            return jComponent;
        }
    }
}
