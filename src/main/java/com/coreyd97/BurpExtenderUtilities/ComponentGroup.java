package com.coreyd97.BurpExtenderUtilities;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.LinkedHashMap;
import java.util.Map;

public class ComponentGroup extends JPanel {

    private final PanelBuilder panelBuilder;
    private final String title;
    private final Map<String, JComponent> preferenceComponentMap;
    private int currentGridY = 1;

    ComponentGroup(PanelBuilder panelBuilder, String title){
        super(new GridBagLayout());
        this.panelBuilder = panelBuilder;
        this.title = title;
        this.preferenceComponentMap = new LinkedHashMap<>();

        if(this.title != null && this.title != "") {
            this.setBorder(BorderFactory.createTitledBorder(title));
        }
    }

    ComponentGroup(PanelBuilder panelBuilder){
        this(panelBuilder, null);
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
        JButton button = this.panelBuilder.createButton(title, actionListener);
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
        JToggleButton button = this.panelBuilder.createToggleButton(title, actionListener);
        this.add(button, constraints);
        return button;
    }

    public <T extends JComponent> T addPreferenceComponent(final String settingName){
        return addPreferenceComponent(settingName, settingName);
    }

    public <T extends JComponent> T addPreferenceComponent(final String settingName, final String label){
        Object value = this.panelBuilder.getPreferences().getSetting(settingName);
        final JComponent component;

        if(value instanceof String){
            component = this.panelBuilder.createPreferenceTextField(settingName);
        }else if(value instanceof Number){
            component = this.panelBuilder.createPreferenceSpinner(settingName);
        }else if(value instanceof Boolean){
            component = this.panelBuilder.createPreferenceCheckBox(settingName, label);

            //Add to panel here because we don't want to add a label like with the other components.
            this.preferenceComponentMap.put(settingName, component);
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.BOTH;
            gbc.gridx = 1;
            gbc.weightx = 1;
            gbc.gridwidth = 2;
            gbc.weighty = 1;
            gbc.gridy = currentGridY;
            this.add(this.preferenceComponentMap.get(settingName), gbc);
            currentGridY++;

            return (T) component;
        }else{
            component = this.panelBuilder.createPreferenceTextField(settingName);
        }


        this.preferenceComponentMap.put(settingName, component);

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
        this.add(this.preferenceComponentMap.get(settingName), gbc);
        currentGridY++;

        return (T) component;
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
