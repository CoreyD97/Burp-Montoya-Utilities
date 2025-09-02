package com.coreyd97.montoyautilities

import java.awt.Color
import java.awt.event.ActionEvent
import java.awt.event.ItemEvent
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import javax.swing.*
import javax.swing.plaf.basic.BasicComboBoxEditor
import javax.swing.undo.UndoManager
import kotlin.Int
import kotlin.String

/**
 * Created by corey on 05/09/17.
 */
class HistoryField(
    preferenceKey: String,
    private val maxHistory: Int,
    private val onBeforeChange: (String) -> Boolean = { true },
    private val onChange: (String) -> Unit = {}
) : JComboBox<String?>() {
    private val history: LinkedHashSet<String> by Preference(preferenceKey, LinkedHashSet<String>())
    private var selected by Preference("${preferenceKey}_selected", "")
    // Suppress listener during programmatic updates
    private var suppressEvents = false

    init {
        this.putClientProperty("JComboBox.isTableCellEditor", true)
        configureComponent()
    }

    private fun configureComponent() {
        this.setModel(HistoryComboModel())
        this.selectedItem = selected
        this.setEditor(object : BasicComboBoxEditor() {
            override fun createEditorComponent(): JTextField {
                val editorComponent = JTextField()
                editorComponent.setOpaque(false)
                val undoManager = UndoManager()
                editorComponent.document.addUndoableEditListener(undoManager)
                editorComponent.addKeyListener(object : KeyAdapter() {
                    override fun keyReleased(e: KeyEvent) {
                        if (e.keyCode == KeyEvent.VK_ENTER) {
                            setSelectedItem(editorComponent.getText())
                        }
                        if (e.keyCode == KeyEvent.VK_ESCAPE) setSelectedItem(null)
                    }
                })
                actionMap.put("Undo", object : AbstractAction("Undo") {
                    override fun actionPerformed(e: ActionEvent) {
                        if (undoManager.canUndo()) undoManager.undo()
                    }
                })
                actionMap.put("Redo", object : AbstractAction("Redo") {
                    override fun actionPerformed(e: ActionEvent) {
                        if (undoManager.canUndo()) undoManager.redo()
                    }
                })

                inputMap.put(KeyStroke.getKeyStroke("control Z"), "Undo")
                inputMap.put(KeyStroke.getKeyStroke("control Y"), "Redo")

                return editorComponent
            }
        })
        this.addItemListener { e: ItemEvent ->
            if (e.stateChange == ItemEvent.SELECTED) {
                val proposed = this.selectedItem as? String ?: return@addItemListener

                // Veto support: if onBeforeChange returns false, revert and exit
                if (!suppressEvents && !onBeforeChange(proposed)) {
                    suppressEvents = true
                    try {
                        // Restore previous selection/visuals
                        this.selectedItem = selected
                        (editor.editorComponent as? JTextField)?.text = selected
                    } finally {
                        suppressEvents = false
                    }
                    return@addItemListener
                }

                (model as HistoryComboModel).addToHistory(proposed)
                selected = proposed
                if(!suppressEvents) onChange(proposed)
            }
        }
        this.setEditable(true)
        this.setOpaque(true)
    }

    /**
     * Programmatically set the value without triggering the change listener
     * or updating history.
     */
    fun setValueSilently(value: String?) {
        suppressEvents = true
        try {
            this.selectedItem = value
        } finally {
            suppressEvents = false
        }
    }

    fun setForegroundColor(color: Color?) {
        this.getEditor().editorComponent.setForeground(color)
    }

    fun setBackgroundColor(color: Color?) {
        this.getEditor().editorComponent.setBackground(color)
    }

    inner class HistoryComboModel : DefaultComboBoxModel<String>() {
        fun addToHistory(entry: String) {
            if (entry.isNullOrBlank()) return
            history.remove(entry) //Remove in case it was already in the list
            history.add(entry) //Add to the top of the list

            while (history.size > maxHistory) history.removeFirst()
            this.fireContentsChanged(entry, 0, history.size)
        }

        override fun getSize(): Int {
            return history.size
        }

        override fun getElementAt(i: Int): String {
            return history.elementAt(history.size-1-i)
        }
    }
}
