package com.coreyd97.montoyautilities;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

import static com.coreyd97.montoyautilities.MontoyaUtilities.montoya;

/**
 * Created by corey on 24/08/17.
 */
public class PopOutPanel extends JPanel {
    private final JPanel componentWrapper;
    private final JLabel placeholder;
    private final JPanel poppedOutNoticePanel;
    private Component component;
    private String title;
    private boolean isPoppedOut;
    private boolean showPlaceholder;
    private JFrame popoutFrame;
    private JMenuItem popoutMenuItem;

    public PopOutPanel(){
        this.setLayout(new BorderLayout());
        this.componentWrapper = new JPanel(new BorderLayout());
        this.add(componentWrapper, BorderLayout.CENTER);
        this.placeholder = new JLabel("Component is popped out.");
        this.placeholder.setHorizontalAlignment(SwingConstants.CENTER);
        this.poppedOutNoticePanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints(0,0,1,1,1,0,GridBagConstraints.CENTER,GridBagConstraints.HORIZONTAL,new Insets(0,0,0,0),0,0);
        this.poppedOutNoticePanel.add(placeholder, gbc);
        gbc = new GridBagConstraints(0,1,1,1,0,0,GridBagConstraints.CENTER,GridBagConstraints.NONE,new Insets(0,0,0,0),0,0);
        this.poppedOutNoticePanel.add(new JButton(new AbstractAction("Locate Window") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                SwingUtilities.invokeLater(() -> {
                    popoutFrame.setState(Frame.NORMAL);
                    popoutFrame.toFront();
                    popoutFrame.requestFocusInWindow();
                });
            }
        }), gbc);

        montoya.extension().registerUnloadingHandler(() -> {
            if (this.popoutFrame == null) return;
            popoutFrame.dispose();
        });
    }

    /**
     * @param component The component to display
     * @param title The title for the popout window
     */
    public PopOutPanel(Component component, String title){
        this(component, title, true);
    }

    /**
     * @param component The component to display
     * @param title The title for the popout window
     * @param showPlaceholder Display a placeholder in place of the component when popped out.
     */
    public PopOutPanel(Component component, String title, boolean showPlaceholder){
        this();
        this.component = component;
        this.title = title;
        this.showPlaceholder = showPlaceholder;
        this.placeholder.setText(title + " is popped out.");
        this.componentWrapper.add(component, BorderLayout.CENTER);
    }

    public void setComponent(Component component) {
        this.component = component;
        this.componentWrapper.add(component, BorderLayout.CENTER);
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
        this.remove(poppedOutNoticePanel);
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
                PopOutPanel.this.remove(componentWrapper);
                if(showPlaceholder) {
                    PopOutPanel.this.add(poppedOutNoticePanel, BorderLayout.CENTER);
                }else{
                }
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
