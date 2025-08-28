package com.coreyd97.montoyautilities

import java.awt.Component
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import javax.swing.BorderFactory
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel

class ComponentGroup(private val orientation: Orientation) : JPanel(GridBagLayout()) {
    enum class Orientation {
        HORIZONTAL, VERTICAL
    }

    private var componentIndex = 1

    constructor(orientation: Orientation, title: String?) : this(orientation) {
        this.border = BorderFactory.createTitledBorder(title)
    }

    enum class ComponentType {
        STRING,
        NUMBER,
        BOOLEAN
    }
    fun <T : JComponent> addPreferenceComponent(
        settingName: String,
        type: ComponentType,
        label: String? = null, fillVertical: Boolean = true
    ): T {

        val component = when (type) {
            ComponentType.STRING -> PanelBuilder.createPreferenceTextField(settingName)
            ComponentType.NUMBER -> PanelBuilder.createPreferenceSpinner(settingName)
            ComponentType.BOOLEAN -> PanelBuilder.createPreferenceCheckBox(settingName)
        }

        addComponentWithLabel(label, component, fillVertical)

        return component as T
    }

    @JvmOverloads
    fun addComponentWithLabel(label: String?, component: Component?, fillVertical: Boolean = false) {
        val gbc = GridBagConstraints()
        gbc.fill = if (fillVertical) GridBagConstraints.BOTH else GridBagConstraints.HORIZONTAL
        if (orientation == Orientation.VERTICAL) {
            gbc.gridx = 1
            gbc.gridy = componentIndex
            gbc.weightx = 0.15
            gbc.weighty = 1.0
        } else {
            gbc.gridx = componentIndex
            gbc.gridy = 1
            gbc.weightx = 1.0
        }
        this.add(JLabel(label), gbc)

        if (orientation == Orientation.VERTICAL) {
            gbc.gridx++
            gbc.weightx = 0.85
        } else {
            gbc.gridy++
        }

        this.add(component, gbc)
        componentIndex++
    }

    /**
     * Generate the constraints for the next element in the group.
     * Useful for customising before addition.
     * @return GridBagConstraints The default constraints for the next item in the group.
     */
    fun generateNextConstraints(fillVertical: Boolean): GridBagConstraints {
        val gbc = GridBagConstraints()
        gbc.fill = if (fillVertical) GridBagConstraints.BOTH else GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        gbc.weighty = gbc.weightx
        gbc.gridwidth = 2
        if (orientation == Orientation.VERTICAL) {
            gbc.gridx = 1
            gbc.gridy = componentIndex
        } else {
            gbc.gridy = 1
            gbc.gridx = componentIndex * 2 //Since we're using 2 width components
        }
        componentIndex++
        return gbc
    }

    override fun add(comp: Component): Component {
        this.add(comp, generateNextConstraints(true))
        return comp
    }

    fun add(comp: Component, fillVertical: Boolean): Component {
        this.add(comp, generateNextConstraints(fillVertical))
        return comp
    }
}
