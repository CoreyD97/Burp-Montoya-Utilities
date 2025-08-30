package com.coreyd97.montoyautilities

import java.awt.Color
import java.awt.event.ActionEvent
import java.awt.event.ItemEvent
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.lang.Boolean
import javax.swing.*
import javax.swing.plaf.basic.BasicComboBoxEditor
import javax.swing.undo.UndoManager
import kotlin.Int
import kotlin.String

/**
 * Created by corey on 05/09/17.
 */
class HistoryField(preferenceKey: String, private val maxHistory: Int) : JComboBox<String?>() {
    private val history by Preference(preferenceKey, mutableListOf<String>())

    init {
        this.putClientProperty("JComboBox.isTableCellEditor", Boolean.TRUE)
        configureComponent()
    }

    private fun configureComponent() {
        this.setModel(HistoryComboModel())
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
                val selectedItem = this.selectedItem as String
                (model as HistoryComboModel).addToHistory(selectedItem)
            }
        }
        this.setEditable(true)
        this.setOpaque(true)
    }

    fun setForegroundColor(color: Color?) {
        this.getEditor().editorComponent.setForeground(color)
    }

    fun setBackgroundColor(color: Color?) {
        this.getEditor().editorComponent.setBackground(color)
    }

    inner class HistoryComboModel : DefaultComboBoxModel<String?>() {
        fun addToHistory(`val`: String) {
            if (`val` == "") return
            history.remove(`val`) //Remove in case it was already in the list
            history.addFirst(`val`) //Add to the top of the list

            while (history.size > maxHistory) history.removeLast()
            this.fireContentsChanged(`val`, 0, history.size)
        }

        override fun getSize(): Int {
            return history.size
        }

        override fun getElementAt(i: Int): String {
            return history[i]
        }
    }
}
