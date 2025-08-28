package com.coreyd97.montoyautilities

import java.awt.*
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import kotlin.random.Random

// Element interface
interface Element {

}

abstract class Container: JPanel(GridBagLayout()), Element {
    val gbc = GridBagConstraints()
    val children = mutableListOf<Element>()

    protected fun <T : Element> initComponent(tag: T, init: T.() -> Unit): T {
        tag.init()
        children.add(tag)
        addChild(tag)
//        val color = Color(Random.nextInt(256), Random.nextInt(256), Random.nextInt(256))
//        with((tag as JComponent)) { //visual debugging aid
//            border = BorderFactory.createCompoundBorder(
//                border,
//                BorderFactory.createLineBorder(color, 3)
//            )
//        }

        return tag
    }

    fun label(text: String, init: JLabel.() -> Unit = {}): JLabel {
        return initComponent(KLabel(text), init)
    }

    fun button(text: String, init: KButton.() -> Unit): KButton {
        return initComponent(KButton(text), init)
    }

    fun textpreference(label: String? = null, prefKey: String, init: KField.() -> Unit = {}){
        lateinit var field: KField
        var preference by PreferenceProxy<String>(prefKey){ _, new ->
            if(field.text != new) field.text = new
        }
        field = field(label, preference, init)
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
    }

    fun field(label: String? = null, text: String, init: KField.() -> Unit): KField {
        val field = KField(text)
        field.init()
        initComponent(row(null) {
            if(label != null) label(label)
            val gbc: GridBagConstraints = gbc.clone() as GridBagConstraints
            gbc.weightx *= 10
            gbc.fill = GridBagConstraints.BOTH
            addChild(field, gbc)
        }) {}
        return field
    }

    fun row(title: String? = null, init: KRow.() -> Unit): KRow {
        return initComponent(KRow(title), init)
    }

    fun kpanel(title: String? = null, init: KPanel.() -> Unit): KPanel {
        return initComponent(KPanel(title), init)
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
    protected val contentPanel = JPanel(GridBagLayout()).also {
        it.border = BorderFactory.createTitledBorder("INNER")
    }

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

class KButton(text: String) : JButton(text), Element {
    
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

fun krow(text: String? = null, init: KRow.() -> Unit): KRow {
    val row = KRow(text)
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
