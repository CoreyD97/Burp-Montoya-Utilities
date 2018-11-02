package com.coreyd97.BurpExtenderBase;

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

        GridBagConstraints alignmentGbc = new GridBagConstraints();
        alignmentGbc.fill = GridBagConstraints.BOTH;
        switch (alignment){
            case TOPLEFT: {
                alignmentGbc.gridx = maxx+1;
                alignmentGbc.gridy = maxy+1;
                alignmentGbc.weightx = Integer.MAX_VALUE;
                alignmentGbc.weighty = Integer.MAX_VALUE;
                break;
            }
            case TOPMIDDLE: {
                alignmentGbc.gridy = maxy+1;
                alignmentGbc.weighty = Integer.MAX_VALUE;
                break;
            }
            case TOPRIGHT: {
                alignmentGbc.gridx = minx-1;
                alignmentGbc.gridy = maxy+1;
                alignmentGbc.weightx = Integer.MAX_VALUE;
                alignmentGbc.weighty = Integer.MAX_VALUE;
                break;
            }
            case MIDDLELEFT: {
                alignmentGbc.gridx = maxx+1;
                alignmentGbc.weightx = Integer.MAX_VALUE;
                break;
            }
            case MIDDLERIGHT: {
                alignmentGbc.gridx = minx-1;
                alignmentGbc.weightx = Integer.MAX_VALUE;
                break;
            }
            case BOTTOMLEFT: {
                alignmentGbc.gridx = maxx+1;
                alignmentGbc.gridy = miny-1;
                alignmentGbc.weightx = Integer.MAX_VALUE;
                alignmentGbc.weighty = Integer.MAX_VALUE;
                break;
            }
            case BOTTOMMIDDLE: {
                alignmentGbc.gridy = miny-1;
                alignmentGbc.weighty = Integer.MAX_VALUE;
                break;
            }
            case BOTTOMRIGHT: {
                alignmentGbc.gridy = miny-1;
                alignmentGbc.gridx = minx-1;
                alignmentGbc.weightx = Integer.MAX_VALUE;
                alignmentGbc.weighty = Integer.MAX_VALUE;
                break;
            }
        }
        containerPanel.add(new JPanel(), alignmentGbc);

        for (JComponent component : constraintsMap.keySet()) {
            GridBagConstraints constraints = constraintsMap.get(component);
            String props = String.format("x: %d, y: %d, w: %d, h: %d", constraints.gridx, constraints.gridy, constraints.gridwidth, constraints.gridheight);
            System.out.println("Adding Panel \"" + ((ComponentGroup) component).title + "\" with props: " + props);
            containerPanel.add(component, constraintsMap.get(component));
        }

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
        int currY = 1;

        private ComponentGroup(String title){
            this();
            this.title = title;
            this.setBorder(BorderFactory.createTitledBorder(title));
        }

        private ComponentGroup(){
            super(new GridBagLayout());
            this.preferences = new LinkedHashMap<>();
        }

        public JComponent addSetting(final String settingName){
            Class clazz = PanelBuilder.this.preferences.getSettingClass(settingName);
            Object value = PanelBuilder.this.preferences.getSetting(settingName);
            final JComponent component;

            if(clazz.isAssignableFrom(String.class)){
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
            }else if(clazz.isAssignableFrom(Integer.class)){
                final JSpinner spinnerComponent = new JSpinner();
                spinnerComponent.setValue(value);
                spinnerComponent.addChangeListener(new ChangeListener() {
                    @Override
                    public void stateChanged(ChangeEvent changeEvent) {
                        PanelBuilder.this.preferences.setSetting(settingName, spinnerComponent.getValue());
                    }
                });
                component = spinnerComponent;
            }else if(clazz.isAssignableFrom(Boolean.class)){
                final JCheckBox checkComponent = new JCheckBox();
                checkComponent.setSelected((Boolean) value);
                checkComponent.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        PanelBuilder.this.preferences.setSetting(settingName, checkComponent.isSelected());
                    }
                });

                component = checkComponent;
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
            gbc.gridy = currY;
            this.add(new JLabel(settingName), gbc);
            gbc.gridx++;
            gbc.weightx = 0.85;
            this.add(this.preferences.get(settingName), gbc);
            currY++;

            return component;
        }

        public JComponent addComponent(JComponent jComponent){
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.BOTH;
            gbc.gridwidth = 2;
            gbc.gridx = 1;
            gbc.gridy = currY;
            this.add(jComponent);
            currY++;
            return jComponent;
        }

        public JComponent addComponent(JComponent jComponent, GridBagConstraints gridBagConstraints){
            this.add(jComponent, gridBagConstraints);
            return jComponent;
        }
    }
}
