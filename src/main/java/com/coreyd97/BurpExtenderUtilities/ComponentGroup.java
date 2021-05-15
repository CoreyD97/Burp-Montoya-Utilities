package com.coreyd97.BurpExtenderUtilities;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;

public class ComponentGroup extends JPanel {

    public enum Orientation {HORIZONTAL, VERTICAL}

    private final Orientation orientation;
    private int componentIndex = 1;

    public ComponentGroup(Orientation orientation){
        super(new GridBagLayout());
        this.orientation = orientation;
    }

    public ComponentGroup(Orientation orientation, String title){
        this(orientation);
        this.setBorder(BorderFactory.createTitledBorder(title));
    }

    public <T extends JComponent> T addPreferenceComponent(final Preferences preferences, final String settingName){
        return addPreferenceComponent(preferences, settingName, settingName, true);
    }

    public <T extends JComponent> T addPreferenceComponent(final Preferences preferences, final String settingName,
                                                           final boolean fillVertical){
        return addPreferenceComponent(preferences, settingName, settingName, fillVertical);
    }

    public <T extends JComponent> T addPreferenceComponent(final Preferences preferences, final String settingName,
                                                           final String label){
        return addPreferenceComponent(preferences, settingName, label, true);
    }

    public <T extends JComponent> T addPreferenceComponent(final Preferences preferences, final String settingName,
                                                           final String label, boolean fillVertical){
        Class clazz = (Class) preferences.getSettingType(settingName);
        final JComponent component;

        if(clazz.equals(String.class)){
            component = PanelBuilder.createPreferenceTextField(preferences, settingName);
        }else if(Number.class.isAssignableFrom(clazz)){
            component = PanelBuilder.createPreferenceSpinner(preferences, settingName);
        }else if(clazz.equals(Boolean.class)){
            component = PanelBuilder.createPreferenceCheckBox(preferences, settingName);
        }else{
            component = PanelBuilder.createPreferenceTextField(preferences, settingName);
        }

        addComponentWithLabel(label, component, fillVertical);

        return (T) component;
    }

    public void addComponentWithLabel(String label, Component component){
        addComponentWithLabel(label, component, false);
    }

    public void addComponentWithLabel(String label, Component component, boolean fillVertical){
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = fillVertical ? GridBagConstraints.BOTH : GridBagConstraints.HORIZONTAL;
        if(orientation == Orientation.VERTICAL) {
            gbc.gridx = 1;
            gbc.gridy = componentIndex;
            gbc.weightx = 0.15;
            gbc.weighty = 1;
        }else{
            gbc.gridx = componentIndex;
            gbc.gridy = 1;
            gbc.weightx = 1;
        }
        this.add(new JLabel(label), gbc);

        if(orientation == Orientation.VERTICAL){
            gbc.gridx++;
            gbc.weightx = 0.85;
        }else{
            gbc.gridy++;
        }

        this.add(component, gbc);
        componentIndex++;
    }


    /**
     * Generate the constraints for the next element in the group.
     * Useful for customising before addition.
     * @return GridBagConstraints The default constraints for the next item in the group.
     */
    public GridBagConstraints generateNextConstraints(boolean fillVertical){
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = fillVertical ? GridBagConstraints.BOTH : GridBagConstraints.HORIZONTAL;
        gbc.weighty = gbc.weightx = 1;
        gbc.gridwidth = 2;
        if(orientation == Orientation.VERTICAL) {
            gbc.gridx = 1;
            gbc.gridy = componentIndex;
        }else{
            gbc.gridy = 1;
            gbc.gridx = componentIndex*2; //Since we're using 2 width components
        }
        componentIndex++;
        return gbc;
    }

    @Override
    public Component add(Component comp) {
        this.add(comp, generateNextConstraints(true));
        return comp;
    }

    public Component add(Component comp, boolean fillVertical) {
        this.add(comp, generateNextConstraints(fillVertical));
        return comp;
    }
}
