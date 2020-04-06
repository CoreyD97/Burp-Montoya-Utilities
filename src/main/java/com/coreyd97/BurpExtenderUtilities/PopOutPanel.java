package com.coreyd97.BurpExtenderUtilities;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;

/**
 * Created by corey on 24/08/17.
 */
public class PopOutPanel extends JPanel {
    private final JPanel componentWrapper;
    private final JLabel placeholder;
    private Component component;
    private String title;
    private boolean isPoppedOut;
    private JFrame popoutFrame;
    private JMenuItem popoutMenuItem;

    public PopOutPanel(){
        this.setLayout(new BorderLayout());
        this.componentWrapper = new JPanel(new BorderLayout());
        this.add(componentWrapper, BorderLayout.CENTER);
        this.placeholder = new JLabel("Component is popped out.");
        this.placeholder.setHorizontalAlignment(SwingConstants.CENTER);
    }

    public PopOutPanel(Component component, String title){
        this();
        this.component = component;
        this.title = title;
        this.placeholder.setText(title + " is popped out.");
        this.componentWrapper.add(component, BorderLayout.CENTER);
    }

    public void setComponent(Component component) {
        this.component = component;
        this.componentWrapper.add(component);
    }

    public void setTitle(String title) {
        this.title = title;
        this.placeholder.setText(title + " is popped out.");
    }

    public void toggle(){
        if (this.isPoppedOut) popIn();
        else popOut();
    }

    public void popIn(){
        this.remove(placeholder);
        this.add(componentWrapper, BorderLayout.CENTER);
        this.revalidate();
        this.repaint();
        this.isPoppedOut = false;
        this.popoutFrame.dispose();
        if(popoutMenuItem != null) popoutMenuItem.setText("Pop Out " + title);
    }

    public void popOut(){
        this.popoutFrame = new JFrame();
        popoutFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        popoutFrame.addWindowListener(new WindowListener() {
            @Override
            public void windowOpened(WindowEvent windowEvent) {
                popoutFrame.add(componentWrapper);
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
        if(popoutMenuItem != null) popoutMenuItem.setText("Pop In " + title);
    }

    public JMenuItem getPopoutMenuItem(){
        if(this.popoutMenuItem == null){
            popoutMenuItem = new JMenuItem((isPoppedOut ? "Pop In " : "Pop Out ") + title);
            popoutMenuItem.addActionListener(e -> {
                this.toggle();
            });
        }

        return popoutMenuItem;
    }

    public JFrame getPopoutFrame() {
        return popoutFrame;
    }

    public boolean isPoppedOut() {
        return isPoppedOut;
    }
}
