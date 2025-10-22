import com.coreyd97.montoyautilities.Alignment
import com.coreyd97.montoyautilities.KPanel
import com.coreyd97.montoyautilities.panelBuilder
import java.awt.BorderLayout
import java.awt.GridLayout
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JFrame
import javax.swing.JPanel
import javax.swing.SwingUtilities

public fun test(): JPanel {
    val panel = JPanel(GridLayout(0,3))

    for (align in Alignment.values()) {
        panel.add(panelBuilder(align.name, align){
            label(align.name)
        })
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
        window.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent?) {
                if (e == null) return
                if (e.button == MouseEvent.BUTTON1) {
                    println("Left click at (${e.x}, ${e.y})")
                } else if (e.button == MouseEvent.BUTTON3) {
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