package com.coreyd97.montoyautilities

import java.awt.*
import javax.swing.*

/**
 * A utility class to display a temporary toast notification in a Swing application.
 */
object ToastNotification {

    /**
     * Shows a toast notification with the given message for a specified duration.
     * The toast is a small, undecorated window that appears at the bottom-center of the screen.
     *
     * @param owner The parent frame for the toast. Can be a JFrame or null.
     * @param message The message to display in the toast.
     * @param durationMillis The duration in milliseconds for which the toast will be visible.
     */
    fun show(owner: Frame?, message: String, durationMillis: Long = 3000) {
        // Create an undecorated JWindow to serve as the toast.
        // It should not have focus and should be always on top.
        val toast = JWindow(owner)
        toast.isAlwaysOnTop = true
        toast.isFocusable = false

        // Create the panel that will hold the message.
        val panel = JPanel().apply {
            background = Color(50, 50, 50, 200) // Semi-transparent black
            layout = BorderLayout()
            border = BorderFactory.createEmptyBorder(10, 20, 10, 20)
        }

        // Create the label for the message.
        val label = JLabel(message, SwingConstants.CENTER).apply {
            foreground = Color.WHITE
            font = font.deriveFont(Font.BOLD, 14f)
        }

        // Add the label to the panel and the panel to the window.
        panel.add(label)
        toast.contentPane = panel
        toast.pack()

        // Calculate the position of the toast at the bottom-center of the screen.
        val screenSize: Dimension = Toolkit.getDefaultToolkit().screenSize
        val x = (screenSize.width - toast.width) / 2
        val y = screenSize.height - toast.height - 50
        toast.location = Point(x, y)

        // Make the toast visible.
        toast.isVisible = true

        // Use a Timer to automatically hide and dispose of the toast after the duration.
        Timer(durationMillis.toInt()) {
            toast.dispose()
        }.apply {
            isRepeats = false
            start()
        }
    }
}