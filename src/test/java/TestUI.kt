import com.coreyd97.montoyautilities.Alignment
import com.coreyd97.montoyautilities.KPanel
import com.coreyd97.montoyautilities.kpanel
import java.awt.BorderLayout
import javax.swing.JFrame
import javax.swing.SwingUtilities

public fun test(): KPanel {
    val panel = kpanel("Test", Alignment.TOPMIDDLE) {
//        gbc.ipadx = 50
//        gbc.ipady = 50

        row {
            // Row initialization
            button("Click Me") {
                // Button initialization

            }
        }
        row {
            // Another row initialization
            field("Name:", "Corey") {
                // Field initialization
            }
        }

        label("This is a label") {
            // Label initialization
        }

        kpanel {
            row {
                label("Nested Panel Label")
                button("Nested Button") {}
            }

            button("Another Button") {}
        }
    }
    return panel
}

fun main() {
    SwingUtilities.invokeLater {
        val window = JFrame()
        window.contentPane.layout = BorderLayout()
        window.contentPane.add(test(), BorderLayout.CENTER)
        window.setSize(400, 300)
        window.setLocationRelativeTo(null)
        window.isVisible = true
        window.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mouseClicked(e: java.awt.event.MouseEvent?) {
                if (e == null) return
                if (e.button == java.awt.event.MouseEvent.BUTTON1) {
                    println("Left click at (${e.x}, ${e.y})")
                } else if (e.button == java.awt.event.MouseEvent.BUTTON3) {
                    println("Right click at (${e.x}, ${e.y})")
                    window.contentPane.removeAll()
                    window.contentPane.add(test())
                    window.revalidate()
                    window.repaint()
                }
            }
        })
    }
}