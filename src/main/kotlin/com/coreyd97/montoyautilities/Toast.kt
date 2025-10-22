package com.coreyd97.montoyautilities

import java.awt.*
import java.lang.IllegalArgumentException
import javax.swing.*

/**
 * A utility class to display a temporary toast notification in a Swing application.
 */
object ToastNotification {

    enum class Placement {
        BELOW, ABOVE, RIGHT, LEFT, OVER_CENTER, SCREEN_BOTTOM_CENTER
    }

    /**
     * New: Show a toast owned/anchored by any Swing component.
     * - If owner is non-null, place relative to that component (default: BELOW).
     * - If owner is null, place at the bottom-center of the screen.
     *
     * @param owner Any Swing component to anchor the toast to (may be null).
     * @param message The text to display.
     * @param durationMillis Time to show the toast.
     * @param placement How to position relative to owner.
     * @param offset Pixel offset from the owner when anchoring near it.
     */
    fun show(
        owner: Component?,
        message: String,
        durationMillis: Long = 3000,
        placement: Placement = Placement.BELOW,
        offset: Int = 8
    ) {
        // Create an undecorated JWindow anchored to the owner's window if possible
        val windowOwner: Window? = when (owner) {
            is Window -> owner
            else -> if (owner != null) SwingUtilities.getWindowAncestor(owner) else null
        }
        val toast = JWindow(windowOwner)
        toast.isAlwaysOnTop = true
        toast.isFocusable = false

        val panel = JPanel().apply {
            background = Color(50, 50, 50, 200) // Semi-transparent black
            layout = BorderLayout()
            border = BorderFactory.createEmptyBorder(10, 20, 10, 20)
        }

        val label = JLabel(message, SwingConstants.CENTER).apply {
            foreground = Color.WHITE
            font = font.deriveFont(Font.BOLD, 14f)
        }


        val screenBounds = (windowOwner ?: GraphicsEnvironment.getLocalGraphicsEnvironment()
            .defaultScreenDevice.defaultConfiguration.device)
            .let {
                // Prefer the owner's screen if available
                val gc: GraphicsConfiguration? = windowOwner?.graphicsConfiguration ?: owner?.graphicsConfiguration
                (gc ?: GraphicsEnvironment.getLocalGraphicsEnvironment().defaultScreenDevice.defaultConfiguration).bounds
            }

        label.maximumSize = Dimension(screenBounds.width - 50, screenBounds.height - 50)
        panel.add(label)
        if(label.preferredSize.width > screenBounds.width || label.preferredSize.height > screenBounds.height) {
            toast.contentPane = JScrollPane(panel)
        }else {
            toast.contentPane = panel
        }
        toast.pack()

        // Compute location
        val targetPoint: Point = if (owner != null) {
            // Owner-relative placement using absolute screen coords
            val base = try {
                owner.locationOnScreen
            } catch (_: IllegalComponentStateException) {
                // Owner not showing; fallback to screen bottom center
                null
            }

            if (base == null) {
                // fallback
                val x = screenBounds.x + (screenBounds.width - toast.width) / 2
                val y = screenBounds.y + screenBounds.height - toast.height - 50
                Point(x, y)
            } else {
                when (placement) {
                    Placement.BELOW -> Point(
                        base.x + (owner.width - toast.width) / 2,
                        base.y + owner.height + offset
                    )
                    Placement.ABOVE -> Point(
                        base.x + (owner.width - toast.width) / 2,
                        base.y - toast.height - offset
                    )
                    Placement.RIGHT -> Point(
                        base.x + owner.width + offset,
                        base.y + (owner.height - toast.height) / 2
                    )
                    Placement.LEFT -> Point(
                        base.x - toast.width - offset,
                        base.y + (owner.height - toast.height) / 2
                    )
                    Placement.OVER_CENTER -> Point(
                        base.x + (owner.width - toast.width) / 2,
                        base.y + (owner.height - toast.height) / 2
                    )
                    Placement.SCREEN_BOTTOM_CENTER -> {
                        val x = screenBounds.x + (screenBounds.width - toast.width) / 2
                        val y = screenBounds.y + screenBounds.height - toast.height - 50
                        Point(x, y)
                    }
                }
            }
        } else {
            // No owner: bottom-center of screen
            val x = screenBounds.x + (screenBounds.width - toast.width) / 2
            val y = screenBounds.y + screenBounds.height - toast.height - 50
            Point(x, y)
        }

        // Clip to visible screen bounds with small margin
        val margin = 4
        var clampedX: Int
        var clampedY: Int
        try {
            clampedX = targetPoint.x.coerceIn(
                screenBounds.x + margin,
                screenBounds.x + screenBounds.width - toast.width - margin
            )
            clampedY = targetPoint.y.coerceIn(
                screenBounds.y + margin,
                screenBounds.y + screenBounds.height - toast.height - margin
            )
        }catch (_: IllegalArgumentException){
            clampedX = screenBounds.x + (screenBounds.width - toast.width) / 2
            clampedY = screenBounds.y + screenBounds.height - toast.height - 50
        }

        toast.location = Point(clampedX, clampedY)
        toast.isVisible = true

        Timer(durationMillis.toInt()) {
            toast.dispose()
        }.apply {
            isRepeats = false
            start()
        }
    }

    /**
     * Backward-compatible overload: accept Frame? and delegate.
     */
    fun show(owner: Frame?, message: String, durationMillis: Long = 3000) {
        show(owner as Component?, message, durationMillis, Placement.SCREEN_BOTTOM_CENTER)
    }
}