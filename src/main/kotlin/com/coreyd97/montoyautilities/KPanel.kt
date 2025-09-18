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
    val gbc = GridBagConstraints().also {
        it.gridx = 0
        it.gridy = 0
    }

    protected fun <T : Element> initComponent(tag: T, weightX: Number? = null,
                                              weightY: Number? = null, init: T.() -> Unit): T {
        val gbc = gbc.clone() as GridBagConstraints
        if(weightX != null) gbc.weightx = weightX.toDouble()
        if(weightY != null) gbc.weighty = weightY.toDouble()
        return initComponent(tag, gbc, init)
    }

    protected fun <T: Element> initComponent(tag: T, gbc: GridBagConstraints, init: T.() -> Unit): T {
        tag.init()
        val gbc = gbc.clone() as GridBagConstraints
        if(tag is Container){
            gbc.insets = Insets(0,0,0,0)
        }
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

    fun fixedSpacer(width: Int = 0, height: Int = 0): KSpacer {
        return initComponent(KSpacer(width, height), init = {})
    }

    fun filler(weightX: Number = 0, weightY: Number = 0) {
        val elem = KSpacer(1,1)
        elem.border = BorderFactory.createTitledBorder("Test")
        val gbclocal = gbc.clone() as GridBagConstraints
        gbclocal.weightx = weightX.toDouble()
        gbclocal.weighty = weightY.toDouble()
        return addChild(elem, gbclocal)
    }

    fun separator(orientation: Int): KSeparator {
        return initComponent(KSeparator(orientation), init = {})
    }

    fun component(comp: Component, weightX: Number = 0.0, weightY: Number = 0.0, init: JComponent.() -> Unit = {}): JComponent {
        return initComponent(KComponent(comp), weightX, weightY, init)
    }

    fun toggleButton(offText: String, onText: String,
                     initial: Boolean = false, weightX: Number = 0.0,
                     onToggle: (Boolean) -> Unit, init: KToggleButton.() -> Unit = {}): KToggleButton {
        val btn = KToggleButton(offText, onText, initial) { new -> onToggle.invoke(new); true }
        return initComponent(btn, weightX, null, init)
}

// Convenience: vetoable builder that sets the beforeToggle hook.
fun toggleButtonVetoable(offText: String, onText: String,
                         initial: Boolean = false, weightX: Number = 0.0,
                         onToggleAttempt: (Boolean) -> Boolean,
                         init: KToggleButton.() -> Unit = {}): KToggleButton {
    val btn = KToggleButton(offText, onText, initial, onToggleAttempt)
    return initComponent(btn, weightX, null, init)
}

    fun toggleButtonByPreference(prefKey: String, offText: String, onText: String,
                                 weightX: Number = 0.0, init: KToggleButton.() -> Unit = {}): KToggleButton {
        var button: KToggleButton? = null
        var pref by PreferenceProxy<Boolean>(prefKey){ _, new ->
            val b = button ?: return@PreferenceProxy
            if (b.isSelected != new) {
                if (SwingUtilities.isEventDispatchThread()) {
                    b.isSelected = new
                } else {
                    SwingUtilities.invokeLater { b.isSelected = new }
                }
            }
        }
        val onToggle: (Boolean) -> Unit = { new ->
            pref = new
        }
        button = toggleButton(offText, onText, pref, weightX, onToggle, init)
        return button!!
    }

    fun checkBox(label: String = "", initial: Boolean = false, onToggle: (Boolean) -> Unit,
                 weightX: Number = 0.0, init: KCheckBox.() -> Unit = {}): KCheckBox {
        return initComponent(KCheckBox(label, initial, onToggle), weightX, null, init)
    }

    fun checkBoxByPreference(label: String = "", prefKey: String,
                             weightX: Number = 0.0, init: KCheckBox.() -> Unit = {}): KCheckBox {
        var checkBox: KCheckBox? = null
        var pref by PreferenceProxy<Boolean>(prefKey) { _, new ->
            val cb = checkBox ?: return@PreferenceProxy
            if (cb.isSelected != new) {
                if (SwingUtilities.isEventDispatchThread()) {
                    cb.isSelected = new
                } else {
                    SwingUtilities.invokeLater { cb.isSelected = new }
                }
            }
        }
        val onToggle: (Boolean) -> Unit = { new ->
            pref = new
        }
        checkBox = checkBox(label, pref, onToggle, weightX, init)
        return checkBox!!
    }

    fun <T: Number> spinner(value: T, min: Comparable<T>?, max: Comparable<T>?, step: T,
                weightX: Number = 0.0,
                init: KSpinner<T>.() -> Unit = {}): KSpinner<T> {
        return initComponent(KSpinner(value, min, max, step), weightX, null, init)
    }

    inline fun <reified T: Number> spinnerByPreference(prefKey: String,
                                        step: T, min: Comparable<T>?, max: Comparable<T>?,
                                        weightX: Number = 0.0, noinline init: KSpinner<T>.() -> Unit = {}): KSpinner<T> {
        var spinner: KSpinner<T>? = null
        var preference by PreferenceProxy(prefKey, serializer = serializer<T>()){ _, new ->
            val sp = spinner ?: return@PreferenceProxy
            if (sp.value != new) {
                val updater = { sp.value = new }
                if (SwingUtilities.isEventDispatchThread()) updater() else SwingUtilities.invokeLater(updater)
            }
        }
        spinner = spinner(preference, min, max, step, weightX, init)
        spinner.addChangeListener {
            @Suppress("UNCHECKED_CAST")
            preference = spinner.value as T
        }
        return spinner
    }

    fun textByPreference(label: String? = null, prefKey: String, weightX: Number = 0.0, init: KField.() -> Unit = {}): KField {
        var field: KField? = null
        var preference by PreferenceProxy<String>(prefKey){ _, new ->
            val f = field ?: return@PreferenceProxy
            if (f.text != new) {
                val updater = { f.text = new }
                if (SwingUtilities.isEventDispatchThread()) updater() else SwingUtilities.invokeLater(updater)
            }
        }
        field = field(label, preference, weightX, init)
        field!!.document.addDocumentListener(object : DocumentListener {
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

    fun row(title: String? = null, weightX: Number? = null, weightY: Number? = null, init: KRow.() -> Unit): KRow {
        return initComponent(KRow(title), weightX, weightY, init)
    }

    fun panel(title: String? = null, weightX: Number? = null, weightY: Number? = null, init: KPanel.() -> Unit): KPanel {
        val panel = KPanel(title)
        val gbc = gbc.clone() as GridBagConstraints
        if(weightX != null) gbc.weightx = weightX.toDouble()
        if(weightY != null) gbc.weighty = weightY.toDouble()
        return initComponent(panel, gbc, init)
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
open class KPanel(title: String? = null, childAlignment: Alignment? = null) : Container() {

    init {
        if (title != null) {
            border = BorderFactory.createTitledBorder(title)
        }
        // Sensible defaults for children: top-left, horizontal fill, small padding, no vertical grab.
        gbc.gridx = 0
        gbc.gridy = 0
        if(childAlignment != null) {
            gbc.anchor = mapToAnchor(childAlignment)
            gbc.weightx = 1.0
            gbc.weighty = 1.0
            if (childAlignment == Alignment.FILL) {
                gbc.fill = GridBagConstraints.BOTH
            }else{
                gbc.fill = GridBagConstraints.NONE
            }
        } else {
            gbc.anchor = GridBagConstraints.FIRST_LINE_START
            gbc.fill = GridBagConstraints.HORIZONTAL
            gbc.weightx = 1.0
        }
        gbc.insets = Insets(1, 2, 1, 2)
    }

    override fun add(comp: Component?): Component {
        assert(comp != null)
        val gbc = gbc.clone() as GridBagConstraints
        if (gbc.fill == GridBagConstraints.NONE) {
            // If nothing specified, default to horizontal fill for nicer layout
            gbc.fill = GridBagConstraints.HORIZONTAL
        }
        add(comp!!, gbc)
        this.gbc.gridy++
        return comp
    }

    override fun addChild(element: Element, gbc: GridBagConstraints) {
        val gbc = gbc.clone() as GridBagConstraints
        add(element as JComponent, gbc)
        this.gbc.gridy++
    }
}

class KRow(title: String? = null) : KPanel(title) {

    override fun add(comp: Component?): Component {
        assert(comp != null)
        val gbc = gbc.clone() as GridBagConstraints
        // Rows default to horizontal fill, lay out left-to-right
        if (gbc.fill == GridBagConstraints.NONE) {
            gbc.fill = GridBagConstraints.HORIZONTAL
        }
        add(comp!!, gbc)
        this.gbc.gridx++
        return comp
    }

    override fun addChild(element: Element, gbc: GridBagConstraints) {
        val gbc = gbc.clone() as GridBagConstraints

        add(element as JComponent, gbc)
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
        val size = Dimension(width.toInt(), height.toInt())
        preferredSize = size
        minimumSize = size
        maximumSize = size
        isOpaque = false
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

class KToggleButton(
    private val offText: String,
    private val onText: String,
    initial: Boolean,
    // Merged listener: return true to commit, false to cancel
    private val onToggleAttempt: (Boolean) -> Boolean
) : JToggleButton(), Element {

    // Guard to prevent recursion when we programmatically revert a canceled toggle
    private var programmaticChange = false

    init {
        this.isSelected = initial
        this.text = if (this.isSelected) onText else offText
        addItemListener { e ->
            if (programmaticChange) return@addItemListener

            val newSelected = (e.stateChange == ItemEvent.SELECTED)

            // Ask the single merged listener; cancel by reverting if not allowed
            val allowed = try { onToggleAttempt(newSelected) } catch (_: Exception) { false }
            if (!allowed) {
                programmaticChange = true
                val oldSelected = !newSelected
                this.isSelected = oldSelected
                this.text = if (oldSelected) onText else offText
                programmaticChange = false
                return@addItemListener
            }

            // Commit UI text; selection is already newSelected
            this.text = if (newSelected) onText else offText
        }
    }
}

class KField(text: String) : JTextField(text), Element {
}

class KLabel(text: String) : JLabel(text), Element {

}

private class KComponent(comp: Component) : JComponent(), Element {
    init {
        this.layout = BorderLayout()
        this.add(comp, BorderLayout.CENTER)
    }
}

// Builder functions
fun kpanel(title: String? = null, childAlignment: Alignment? = null, init: KPanel.() -> Unit): KPanel {
    val panel = KPanel(title, childAlignment)
    panel.init()
    return panel
}

//fun krow(title: String?, init: KRow.() -> Unit): KRow {
//    val row = KRow(title)
//    row.init()
//    return row
//}

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
