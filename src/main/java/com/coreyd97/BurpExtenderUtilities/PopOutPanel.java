package com.coreyd97.BurpExtenderUtilities;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;

/**
 * Created by corey on 24/08/17.
 */
public class PopOutPanel extends JPanel {
    private final Component component;
    private final JLabel placeholder;
    private String title;
    private boolean isPoppedOut;
    private JFrame popoutFrame;

    public PopOutPanel(Component component, String title){
        this.component = component;
        this.title = title;
        this.placeholder = new JLabel(title + " is popped out.");
        this.placeholder.setHorizontalAlignment(SwingConstants.CENTER);
        this.setLayout(new BorderLayout());
        this.add(component, BorderLayout.CENTER);
    }

    public void toggle(){
        if (this.isPoppedOut) popIn();
        else popOut();
    }

    public void popIn(){
        this.remove(placeholder);
        this.add(component, BorderLayout.CENTER);
        this.revalidate();
        this.repaint();
        this.isPoppedOut = false;
        this.popoutFrame.dispose();
    }

    public void popOut(){
        this.popoutFrame = new JFrame();
        popoutFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        popoutFrame.addWindowListener(new WindowListener() {
            @Override
            public void windowOpened(WindowEvent windowEvent) {
                popoutFrame.add(component);
                isPoppedOut = true;
                PopOutPanel.this.add(placeholder, BorderLayout.CENTER);
                PopOutPanel.this.revalidate();
                PopOutPanel.this.repaint();
                popoutFrame.pack();
            }

            @Override
            public void windowClosing(WindowEvent windowEvent) {
                if(isPoppedOut) popIn();
            }

            @Override
            public void windowClosed(WindowEvent windowEvent) {}

            @Override
            public void windowIconified(WindowEvent windowEvent) {}

            @Override
            public void windowDeiconified(WindowEvent windowEvent) {}

            @Override
            public void windowActivated(WindowEvent windowEvent) {}

            @Override
            public void windowDeactivated(WindowEvent windowEvent) {}
        });

        popoutFrame.setVisible(true);
    }

    public JFrame getPopoutFrame() {
        return popoutFrame;
    }

    public boolean isPoppedOut() {
        return isPoppedOut;
    }
}
