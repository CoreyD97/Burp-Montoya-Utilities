package com.coreyd97.montoyautilities

import kotlinx.serialization.serializer
import java.awt.*
import java.awt.event.ItemEvent
import javax.swing.*
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

// Element interface
interface Element {

}

abstract class Container: JPanel(GridBagLayout()), Element {
    val gbc = GridBagConstraints()

    protected fun <T : Element> initComponent(tag: T, weightX: Number? = null,
                                              weightY: Number? = null, init: T.() -> Unit): T {
        tag.init()
        val gbc = gbc.clone() as GridBagConstraints
        if(weightX != null) gbc.weightx = weightX.toDouble()
        if(weightY != null) gbc.weighty = weightY.toDouble()
        addChild(tag, gbc)
//        val color = Color(Random.nextInt(256), Random.nextInt(256), Random.nextInt(256))
//        with((tag as JComponent)) { //visual debugging aid
//            border = BorderFactory.createCompoundBorder(
//                border,
//                BorderFactory.createLineBorder(color, 3)
//            )
//        }

        return tag
    }

    fun label(text: String, weightX: Number = 0.0, init: JLabel.() -> Unit = {}): JLabel {
        return initComponent(KLabel(text), weightX, null, init)
    }

    fun button(text: String, onClick: () -> Unit, weightX: Number = 0.0, init: KButton.() -> Unit = {}): KButton {
        return initComponent(KButton(text, onClick), weightX, null, init)
    }

    fun spacer(width: Int = 0, height: Int = 0): KSpacer {
        return initComponent(KSpacer(width, height), init = {})
    }

    fun separator(orientation: Int): KSeparator {
        return initComponent(KSeparator(orientation), init = {})
    }

    fun toggleButton(offText: String, onText: String,
                     initial: Boolean = false, weightX: Number = 0.0,
                     onToggle: (Boolean) -> Unit, init: KToggleButton.() -> Unit = {}): KToggleButton {
        val btn = KToggleButton(offText, onText, initial, onToggle)
        return initComponent(btn, weightX, null, init)
    }

    fun toggleButtonByPreference(prefKey: String, offText: String, onText: String,
                                 weightX: Number = 0.0, init: KToggleButton.() -> Unit = {}): KToggleButton {
        lateinit var button: KToggleButton
        var pref by PreferenceProxy<Boolean>(prefKey){ _, new ->
            if(button.isSelected != new)
                button.isSelected = new
        }
        val onToggle: (Boolean) -> Unit = { new ->
            pref = new
        }
        button = toggleButton(offText, onText, pref, weightX, onToggle, init)
        return button
    }

    fun checkBox(label: String = "", initial: Boolean = false, onToggle: (Boolean) -> Unit,
                 weightX: Number = 0.0, init: KCheckBox.() -> Unit = {}): KCheckBox {
        return initComponent(KCheckBox(label, initial, onToggle), weightX, null, init)
    }

    fun checkBoxByPreference(label: String = "", prefKey: String,
                             weightX: Number = 0.0, init: KCheckBox.() -> Unit = {}): KCheckBox {
        lateinit var checkBox: KCheckBox
        var pref by PreferenceProxy<Boolean>(prefKey) { _, new ->
            if(checkBox.isSelected != new)
                checkBox.isSelected = new
        }
        val onToggle: (Boolean) -> Unit = { new ->
            pref = new
        }
        checkBox = checkBox(label, pref, onToggle, weightX, init)
        return checkBox
    }

    fun <T: Number> spinner(value: T, min: Comparable<T>?, max: Comparable<T>?, step: T,
                weightX: Number = 0.0,
                init: KSpinner<T>.() -> Unit = {}): KSpinner<T> {
        return initComponent(KSpinner(value, min, max, step), weightX, null, init)
    }

    inline fun <reified T: Number> spinnerByPreference(prefKey: String,
                                        step: T, min: Comparable<T>?, max: Comparable<T>?,
                                        weightX: Number = 0.0, noinline init: KSpinner<T>.() -> Unit = {}): KSpinner<T> {
        lateinit var spinner: KSpinner<T>
        var preference by PreferenceProxy(prefKey, serializer = serializer<T>()){ _, new ->
            if(spinner.value != new) spinner.value = new
        }
        spinner = spinner(preference, min, max, step, weightX, init)
        spinner.addChangeListener {
            preference = spinner.value as T
        }
        return spinner
    }

    fun textByPreference(label: String? = null, prefKey: String, weightX: Number = 0.0, init: KField.() -> Unit = {}): KField {
        lateinit var field: KField
        var preference by PreferenceProxy<String>(prefKey){ _, new ->
            if(field.text != new) field.text = new
        }
        field = field(label, preference, weightX, init)
        field.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) {
                preference = field.text
            }

            override fun removeUpdate(e: DocumentEvent?) {
                preference = field.text
            }

            override fun changedUpdate(e: DocumentEvent?) {
                preference = field.text
            }

        })
        return field
    }

    fun field(label: String? = null, text: String, weightX: Number = 0.0, init: KField.() -> Unit): KField {
        val field = KField(text)
        field.init()
        //Our row should be the one we control the weight of
        initComponent(row(null, weightX) {
            if(label != null) label(label)
            val gbc: GridBagConstraints = gbc.clone() as GridBagConstraints
            //Our field should fill the row. Label is 0.0
            gbc.weightx = 1.0
            gbc.fill = GridBagConstraints.BOTH
            addChild(field, gbc)
        }) {}
        return field
    }

    fun row(title: String? = null, weightY: Number = 0.0, init: KRow.() -> Unit): KRow {
        return initComponent(KRow(title), null, weightY, init)
    }

    fun kpanel(title: String? = null, weightY: Number = 0.0, init: KPanel.() -> Unit): KPanel {
        return initComponent(KPanel(title), null, weightY, init)
    }

    abstract fun addChild(element: Element, gbc: GridBagConstraints = this.gbc)
}

enum class Alignment {
    TOPLEFT, TOPMIDDLE, TOPRIGHT,
    MIDDLELEFT, CENTER, MIDDLERIGHT,
    BOTTOMLEFT, BOTTOMMIDDLE, BOTTOMRIGHT,
    FILL
}

// Concrete GUI elements
open class KPanel(title: String? = null, alignment: Alignment? = null) : Container() {
    protected val contentPanel = JPanel(GridBagLayout())

    init {
        val outerGbc = GridBagConstraints()
        outerGbc.gridx = 0
        outerGbc.gridy = 0
        if(alignment != null) {
            outerGbc.anchor = mapToAnchor(alignment) //TODO: map alignment to anchor
            if(alignment == Alignment.FILL) {
                outerGbc.fill = GridBagConstraints.BOTH
                outerGbc.weightx = 1.0
                outerGbc.weighty = 1.0
            }else{
                outerGbc.weightx = 0.0
                outerGbc.weighty = 0.0
            }
        }else{
            //Default to filling horizontal space...
            outerGbc.weightx = 1.0
            outerGbc.weighty = 1.0
            outerGbc.fill = GridBagConstraints.HORIZONTAL
        }

        super.add(contentPanel, outerGbc)

        if (title != null) {
            contentPanel.border = BorderFactory.createTitledBorder(title)
        }
        // Default constraints for children
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 1.0
        gbc.weighty = 0.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.NORTHWEST
    }

    override fun add(comp: Component?): Component {
        assert(comp != null)
        val gbc = gbc.clone() as GridBagConstraints
        contentPanel.add(comp!!, gbc)
        this.gbc.gridy++
        return comp!!
    }

    override fun addChild(element: Element, gbc: GridBagConstraints) {
        val gbc = gbc.clone() as GridBagConstraints
        if(element is Container){
            gbc.weightx = 1.0
            gbc.weighty = 1.0
            gbc.fill = GridBagConstraints.BOTH
        }
        if(element is KLabel){
            gbc.fill = GridBagConstraints.HORIZONTAL
        }
        contentPanel.add(element as JComponent, gbc)
        this.gbc.gridy++
    }
}

class KRow(title: String? = null) : KPanel(title) {

    override fun add(comp: Component?): Component {
        assert(comp != null)
        val gbc = gbc.clone() as GridBagConstraints
        contentPanel.add(comp!!, gbc)
        this.gbc.gridx++
        return comp
    }

    override fun addChild(element: Element, gbc: GridBagConstraints) {
        val gbc = gbc.clone() as GridBagConstraints
        if(element is Container){
            gbc.weightx = 1.0
            gbc.weighty = 1.0
            gbc.fill = GridBagConstraints.BOTH
        }
        contentPanel.add(element as JComponent, gbc)
        this.gbc.gridx++
    }
}

class KSpinner<T : Number>(initial: T, min: Comparable<T>?,
               max: Comparable<T>?, step: T): JSpinner(), Element {
    init {
        this.model = SpinnerNumberModel(initial, min, max, step)
    }
}

class KCheckBox(label: String = "", checked: Boolean,
                onToggle: (Boolean) -> Unit): JCheckBox(label, checked), Element {
    init {
        addItemListener { e ->
            onToggle.invoke(e.stateChange == ItemEvent.SELECTED)
        }
    }
}

class KSpacer(width: Number = 0, height: Number = 0): JPanel(), Element {
    init {
        add(Box.createHorizontalStrut(width.toInt()))
        add(Box.createVerticalStrut(height.toInt()))
    }
}

class KSeparator(orientation: Int): JSeparator(orientation), Element


class KButton(text: String, onClick: () -> Unit) : JButton(text), Element {
    init {
        addActionListener {
            onClick.invoke()
        }
    }
}

class KToggleButton(private val offText: String, private val onText: String,
                    initial: Boolean, onToggle: (Boolean) -> Unit) : JToggleButton(), Element {
    init {
        this.isSelected = initial
        this.text = if(this.isSelected) onText else offText
        addItemListener { e ->
            this.text = when(e.stateChange){
                ItemEvent.SELECTED -> onText
                ItemEvent.DESELECTED -> offText
                else -> ""
            }
            onToggle.invoke(e.stateChange == ItemEvent.SELECTED)
        }
    }
}

class KField(text: String) : JTextField(text), Element {
}

class KLabel(text: String) : JLabel(text), Element {

}

// Builder functions
fun kpanel(title: String? = null, alignment: Alignment? = null, init: KPanel.() -> Unit): KPanel {
    val panel = KPanel(title, alignment)
    panel.init()
    return panel
}

fun krow(title: String?, init: KRow.() -> Unit): KRow {
    val row = KRow(title)
    row.init()
    return row
}

fun mapToAnchor(alignment: Alignment): Int {
    return when (alignment) {
        Alignment.TOPLEFT -> GridBagConstraints.FIRST_LINE_START
        Alignment.TOPMIDDLE -> GridBagConstraints.PAGE_START
        Alignment.TOPRIGHT -> GridBagConstraints.FIRST_LINE_END
        Alignment.MIDDLELEFT -> GridBagConstraints.LINE_START
        Alignment.CENTER -> GridBagConstraints.CENTER
        Alignment.MIDDLERIGHT -> GridBagConstraints.LINE_END
        Alignment.BOTTOMLEFT -> GridBagConstraints.LAST_LINE_START
        Alignment.BOTTOMMIDDLE -> GridBagConstraints.PAGE_END
        Alignment.BOTTOMRIGHT -> GridBagConstraints.LAST_LINE_END
        Alignment.FILL -> GridBagConstraints.CENTER // Not really applicable for FILL
    }
}
