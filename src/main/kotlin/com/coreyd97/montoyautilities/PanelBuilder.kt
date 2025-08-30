package com.coreyd97.montoyautilities

import java.awt.Component
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.ActionEvent
import javax.swing.*
import javax.swing.event.ChangeEvent
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

class PanelBuilder {
    private lateinit var componentGrid: MutableList<MutableList<Component?>>
    private lateinit var gridWeightsX: MutableList<IntArray>
    private lateinit var gridWeightsY: MutableList<IntArray>
    var alignment: Alignment = Alignment.CENTER
    var scaleX: Double = 1.0
        set(value) {
            require(!(value > 1 || value < 0)) { "Scale must be between 0 and 1" }
            field = value
        }
    var scaleY: Double = 1.0
        set(value) {
            require(!(value > 1 || value < 0)) { "Scale must be between 0 and 1" }
            field = value
        }
    var insetsX: Int = 0
    var insetsY: Int = 0

    fun addComponentRow(components: List<Component?>,
                        xWeights: List<Int>? = null,
                        yWeights: List<Int>? = null): PanelBuilder {
        if (!this::componentGrid.isInitialized) {
            this.componentGrid = mutableListOf()
        }
        this.componentGrid.add(components.toMutableList())
        if (xWeights != null) {
            if (!this::gridWeightsX.isInitialized) {
                this.gridWeightsX = mutableListOf()
            }
            this.gridWeightsX.add(xWeights.toIntArray())
        }
        if (yWeights != null) {
            if (!this::gridWeightsY.isInitialized) {
                this.gridWeightsY = mutableListOf()
            }
            this.gridWeightsY.add(yWeights.toIntArray())
        }
        return this
    }

    fun setComponentGrid(componentGrid: List<List<Component?>>): PanelBuilder {
        this.componentGrid = componentGrid.map { it.toMutableList() }.toMutableList()
        return this
    }

    fun setGridWeightsX(gridWeightsX: List<IntArray>): PanelBuilder {
        this.gridWeightsX = gridWeightsX.toMutableList()
        return this
    }

    fun setGridWeightsY(gridWeightsY: List<IntArray>): PanelBuilder {
        this.gridWeightsY = gridWeightsY.toMutableList()
        return this
    }

    fun setInsetsX(insetsX: Int): PanelBuilder {
        this.insetsX = insetsX
        return this
    }

    fun setInsetsY(insetsY: Int): PanelBuilder {
        this.insetsY = insetsY
        return this
    }

    public fun build(): JPanel {
        val containerPanel = JPanel(GridBagLayout())
        val constraintsMap = HashMap<Component, GridBagConstraints>()
        var minx = Int.MAX_VALUE
        var miny = Int.MAX_VALUE
        var maxx = Int.MIN_VALUE
        var maxy = Int.MIN_VALUE

        for (row in componentGrid.indices) {
            for (column in componentGrid[row].indices) {
                val panel = componentGrid[row][column]
                if (panel != null) {
                    val gridx = column + 1
                    val gridy = row + 1

                    if (constraintsMap.containsKey(panel)) {
                        val constraints = constraintsMap[panel]
                        if (gridx < constraints!!.gridx || (constraints.gridx + constraints.gridwidth) < gridx) {
                            throw RuntimeException("Panels must be contiguous.")
                        }
                        if (gridy < constraints.gridy || (constraints.gridy + constraints.gridheight) < gridy) {
                            throw RuntimeException("Panels must be contiguous.")
                        }

                        constraints.gridwidth = gridx - constraints.gridx + 1
                        constraints.gridheight = gridy - constraints.gridy + 1
                        try {
                            constraints.weightx = gridWeightsX[gridy - 1][gridx - 1].toDouble()
                        } catch (e: Exception) {
                        }

                        try {
                            constraints.weighty = gridWeightsY[gridy - 1][gridx - 1].toDouble()
                        } catch (e: Exception) {
                        }
                    } else {
                        val constraints = GridBagConstraints()
                        constraints.fill = GridBagConstraints.BOTH
                        constraints.gridx = gridx
                        constraints.gridy = gridy
                        try {
                            constraints.weightx = gridWeightsX[gridy - 1][gridx - 1].toDouble()
                        } catch (e: Exception) {
                        }

                        try {
                            constraints.weighty = gridWeightsY[gridy - 1][gridx - 1].toDouble()
                        } catch (e: Exception) {
                        }
                        constraints.insets = Insets(insetsY, insetsX, insetsY, insetsX)
                        constraintsMap[panel] = constraints
                    }

                    if (gridx < minx) minx = gridx
                    if (gridx > maxx) maxx = gridx
                    if (gridy < miny) miny = gridy
                    if (gridy > maxy) maxy = gridy
                } else {
                    val constraints = GridBagConstraints()
                    constraints.gridx = column + 1
                    constraints.gridy = row + 1
                    constraints.fill = GridBagConstraints.BOTH
                    constraints.weighty = 1.0
                    constraints.weightx = constraints.weighty
                    val filler = JPanel()
                    constraintsMap[filler] = constraints
                }
            }
        }

        val innerPanelGbc = GridBagConstraints()
        innerPanelGbc.fill = GridBagConstraints.BOTH
        innerPanelGbc.gridy = 2
        innerPanelGbc.gridx = innerPanelGbc.gridy
        innerPanelGbc.weightx = scaleX
        innerPanelGbc.weighty = scaleY
        val paddingLeftGbc = GridBagConstraints()
        val paddingRightGbc = GridBagConstraints()
        val paddingTopGbc = GridBagConstraints()
        val paddingBottomGbc = GridBagConstraints()
        paddingBottomGbc.fill = GridBagConstraints.BOTH
        paddingTopGbc.fill = paddingBottomGbc.fill
        paddingRightGbc.fill = paddingTopGbc.fill
        paddingLeftGbc.fill = paddingRightGbc.fill
        paddingRightGbc.weightx = (1 - scaleX) / 2
        paddingLeftGbc.weightx = paddingRightGbc.weightx
        paddingBottomGbc.weighty = (1 - scaleY) / 2
        paddingTopGbc.weighty = paddingBottomGbc.weighty
        paddingRightGbc.gridy = 2
        paddingLeftGbc.gridy = paddingRightGbc.gridy
        paddingBottomGbc.gridx = 2
        paddingTopGbc.gridx = paddingBottomGbc.gridx
        paddingLeftGbc.gridx = 1
        paddingRightGbc.gridx = 3
        paddingTopGbc.gridy = 1
        paddingBottomGbc.gridy = 3

        var topPanel: JPanel?
        var leftPanel: JPanel?
        var bottomPanel: JPanel?
        var rightPanel: JPanel?

        if (alignment != Alignment.FILL && alignment != Alignment.TOPLEFT && alignment != Alignment.TOPMIDDLE && alignment != Alignment.TOPRIGHT) {
            containerPanel.add(JPanel().also { topPanel = it }, paddingTopGbc)
            //            topPanel.setBorder(BorderFactory.createLineBorder(Color.BLUE));
        }

        if (alignment != Alignment.FILL && alignment != Alignment.TOPLEFT && alignment != Alignment.MIDDLELEFT && alignment != Alignment.BOTTOMLEFT) {
            containerPanel.add(JPanel().also { leftPanel = it }, paddingLeftGbc)
            //            leftPanel.setBorder(BorderFactory.createLineBorder(Color.BLUE));
        }

        if (alignment != Alignment.FILL && alignment != Alignment.TOPRIGHT && alignment != Alignment.MIDDLERIGHT && alignment != Alignment.BOTTOMRIGHT) {
            containerPanel.add(JPanel().also { rightPanel = it }, paddingRightGbc)
            //            rightPanel.setBorder(BorderFactory.createLineBorder(Color.BLUE));
        }

        if (alignment != Alignment.FILL && alignment != Alignment.BOTTOMLEFT && alignment != Alignment.BOTTOMMIDDLE && alignment != Alignment.BOTTOMRIGHT) {
            containerPanel.add(JPanel().also { bottomPanel = it }, paddingBottomGbc)
            //            bottomPanel.setBorder(BorderFactory.createLineBorder(Color.ORANGE));
        }


        val innerContainer = JPanel(GridBagLayout())
        for (component in constraintsMap.keys) {
            innerContainer.add(component, constraintsMap[component])
        }
        containerPanel.add(innerContainer, innerPanelGbc)

        return containerPanel
    }

    companion object {

        /**
         * com.coreyd97.montoyautilities.Preference components
         */
        fun createPreferenceToggleButton(title: String, preferenceKey: String,
                                         onChange: ((source: JToggleButton, enabled: Boolean) -> Unit)? = null): JToggleButton {
            lateinit var toggleButton: JToggleButton
            var pref: Boolean by PreferenceProxy(preferenceKey){ _, new ->
                onChange?.invoke(toggleButton, new)
            }
            toggleButton = JToggleButton(title).also {
                it.action = object : AbstractAction(title) {
                    override fun actionPerformed(actionEvent: ActionEvent) {
                        pref = (actionEvent.source as JToggleButton).isSelected
                    }
                }
                it.isSelected = pref
            }
            return toggleButton
        }

        fun createPreferenceTextField(preferenceKey: String): JTextField {
            var pref: String by PreferenceProxy(preferenceKey)
            val textComponent = JTextField().also {
                it.text = pref
                it.document.addDocumentListener(object : DocumentListener {
                    override fun insertUpdate(documentEvent: DocumentEvent) {
                        pref = it.text
                    }

                    override fun removeUpdate(documentEvent: DocumentEvent) {
                        pref = it.text
                    }

                    override fun changedUpdate(documentEvent: DocumentEvent) {
                        pref = it.text
                    }
                })
            }

//            preferences.addSettingListener { eventSource, settingName, newValue ->
//                if (textComponent != eventSource && settingName.equals(preferenceKey)) {
//                    textComponent.text = newValue
//                }
//            }

            return textComponent
        }

        fun createPreferencePasswordField(preferenceKey: String): JPasswordField {
            var pref: String by PreferenceProxy(preferenceKey)
            val textComponent = JPasswordField().also {
                it.text = pref
                it.document.addDocumentListener(object : DocumentListener {
                    override fun insertUpdate(documentEvent: DocumentEvent) {
                        pref = String(it.password)
                    }

                    override fun removeUpdate(documentEvent: DocumentEvent) {
                        pref = String(it.password)
                    }

                    override fun changedUpdate(documentEvent: DocumentEvent) {
                        pref = String(it.password)
                    }
                })
            }
//            preferences.addSettingListener { eventSource, settingName, newValue ->
//                if (textComponent != eventSource && settingName.equals(preferenceKey)) {
//                    textComponent.text = java.lang.String.valueOf(newValue)
//                }
//            }

            return textComponent
        }

        fun createPreferenceSpinner(preferenceKey: String): JSpinner {
            var pref: Int by PreferenceProxy(preferenceKey)
            val spinnerComponent = JSpinner().also {
                it.value = pref
                it.addChangeListener { changeEvent: ChangeEvent? ->
                    pref = it.value as Int
                }
            }

//            preferences.addSettingListener { eventSource, settingName, newValue ->
//                if (spinnerComponent != eventSource && settingName.equals(preferenceKey)) {
//                    spinnerComponent.value = newValue
//                }
//            }

            return spinnerComponent
        }

        fun createPreferenceCheckBox(preferenceKey: String, label: String? = null): JCheckBox {
            var value: Boolean by PreferenceProxy(preferenceKey)
            val checkComponent = JCheckBox(label)
            checkComponent.isSelected = value
            checkComponent.addActionListener {
                value = checkComponent.isSelected
            }

//            preferences.addSettingListener { eventSource, changedSettingName, newValue ->
//                if (checkComponent != eventSource && changedSettingName.equals(preferenceKey)) {
//                    checkComponent.isSelected = newValue
//                }
//            }

            return checkComponent
        }

        fun createPreferenceTextArea(settingName: String): JTextArea {
            var value: String by PreferenceProxy(settingName)

            val textArea = JTextArea(value).also {
                it.lineWrap = true
                it.wrapStyleWord = true

                it.document.addDocumentListener(object : DocumentListener {
                    override fun insertUpdate(documentEvent: DocumentEvent) {
                        value = it.text
                    }

                    override fun removeUpdate(documentEvent: DocumentEvent) {
                        value = it.text
                    }

                    override fun changedUpdate(documentEvent: DocumentEvent) {
                        value = it.text
                    }
                })
            }

//            preferences.addSettingListener { eventSource, changedKey, newValue ->
//                if (textArea != eventSource && changedKey.equals(settingName)) {
//                    textArea.text = newValue
//                }
//            }

            return textArea
        }
    }
}
