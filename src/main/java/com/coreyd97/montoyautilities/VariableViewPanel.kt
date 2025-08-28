package com.coreyd97.montoyautilities

import java.awt.BorderLayout
import java.awt.Component
import javax.swing.JPanel
import javax.swing.JSplitPane
import javax.swing.JTabbedPane

/**
 * Created by corey on 24/08/17.
 */
class VariableViewPanel(
    preferenceKey: String,
    private val a: Component, private val aTitle: String, private val b: Component, private val bTitle: String,
    defaultView: View = View.VERTICAL
) : JPanel() {
    enum class View {
        HORIZONTAL, VERTICAL, TABS
    }

    private var wrapper: Component? = null
    private var _view: View by Preference(preferenceKey, defaultView)
    public var view: View = _view
        get() = _view
        set(value) {
            field = value
            updateView(value)
        }

    init {
        this.layout = BorderLayout()
        this.updateView(_view)
    }

    private fun updateView(view: View) {
        when (view) {
            View.HORIZONTAL, View.VERTICAL -> {
                this.wrapper = JSplitPane()
                (wrapper as JSplitPane).leftComponent = a
                (wrapper as JSplitPane).rightComponent = b
                if (view == View.HORIZONTAL) {
                    (wrapper as JSplitPane).orientation = JSplitPane.HORIZONTAL_SPLIT
                } else {
                    (wrapper as JSplitPane).orientation = JSplitPane.VERTICAL_SPLIT
                }
                (wrapper as JSplitPane).resizeWeight = 0.5
            }

            View.TABS -> {
                this.wrapper = JTabbedPane()
                (wrapper as JTabbedPane).addTab(aTitle, a)
                (wrapper as JTabbedPane).addTab(bTitle, b)
            }
        }
        this.removeAll()
        this.add(wrapper, BorderLayout.CENTER)
        this.revalidate()
        this.repaint()
        this._view = view
    }
}
