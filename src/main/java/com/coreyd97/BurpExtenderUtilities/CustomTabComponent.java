package com.coreyd97.BurpExtenderUtilities;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.function.Consumer;

public class CustomTabComponent extends JPanel {

    private final JTabbedPane parentPane;
    private JLabel indexLabel;
    private final JPanel labelWrapper;
    private final JLabel label;
    private JTextField editableField;
    private JButton removeTabButton;

    private int index;
    private boolean showIndex;
    private boolean isEditable;
    private Consumer<String> onTitleChanged;
    private boolean isRemovable;
    private Consumer<Void> onRemovePressed;

    private boolean wasEdited;

    public CustomTabComponent(JTabbedPane parentPane, int index, String title,
                              boolean showIndex,
                              boolean isEditable, Consumer<String> onTitleChanged,
                              boolean isRemovable, Consumer<Void> onRemovePressed){
        super(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        this.setOpaque(false);
        this.parentPane = parentPane;
        this.index = index;
        this.showIndex = showIndex;
        this.isEditable = isEditable;
        this.onTitleChanged = onTitleChanged;
        this.isRemovable = isRemovable;
        this.onRemovePressed = onRemovePressed;
        this.wasEdited = false;

        if(this.showIndex){
            indexLabel = new JLabel(index + ": ");
            this.add(indexLabel);
        }

        this.labelWrapper = new JPanel();
        this.labelWrapper.setOpaque(false);
        add(labelWrapper);

        label = new JLabel(title);
        label.setOpaque(false);
        labelWrapper.add(label);

        if(this.isEditable) {
            label.addMouseListener(new editClickListener());
            this.addMouseListener(new editClickListener());

            editableField = new JTextField();
            editableField.setBorder(null);
            editableField.setOpaque(false);
            editableField.addFocusListener(new FocusAdapter() {
                @Override
                public void focusLost(FocusEvent focusEvent) {
                    endEditLabel();
                }
            });
            editableField.addKeyListener(new KeyAdapter() {
                @Override
                public void keyReleased(KeyEvent keyEvent) {
                    if(keyEvent.getExtendedKeyCode() == KeyEvent.VK_ENTER){
                        endEditLabel();
                    }
                }
            });
        }

        if(this.isRemovable) {
            removeTabButton = new JButton("x");
            removeTabButton.addActionListener(actionEvent -> {
                if(this.onRemovePressed != null)
                    this.onRemovePressed.accept(null);
            });
            removeTabButton.setPreferredSize(new Dimension(25,25));
            removeTabButton.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
            add(Box.createHorizontalStrut(5));
            add(removeTabButton);
        }

        revalidate();
        repaint();

    }

    private void editLabel(){
        editableField.setText(label.getText());
        editableField.setOpaque(false);
        labelWrapper.remove(label);
        labelWrapper.add(editableField);
        editableField.setCaretPosition(0);
        editableField.requestFocus();
    }

    private void endEditLabel(){
        if(!editableField.getText().equalsIgnoreCase(this.label.getText())){
            wasEdited = true;
        }
        String newTitle = editableField.getText();
        this.label.setText(newTitle);
        if(this.onTitleChanged != null)
            this.onTitleChanged.accept(newTitle);

        labelWrapper.remove(editableField);
        labelWrapper.add(label);
        this.invalidate();
        this.repaint();
    }


    private class editClickListener extends MouseAdapter {
        @Override
        public void mousePressed(MouseEvent mouseEvent) {
            super.mouseClicked(mouseEvent);
            if(mouseEvent.getClickCount() > 1) {
                editLabel();
            }else{
                //For some reason, Custom tab components with mouselisteners
                //do not bubble up to select the tab. This kind of fixes that.
                if(CustomTabComponent.this.parentPane != null){
                    for (int i = 0; i < parentPane.getTabCount(); i++) {
                        if(parentPane.getTabComponentAt(i) == CustomTabComponent.this){
                            parentPane.setSelectedIndex(i);
                            parentPane.requestFocus(true);
                            return;
                        }
                    }
                }
            }
        }
    }

    public void setIndex(int index) {
        this.index = index;
        if(this.showIndex){
            this.indexLabel.setText(index + ": ");
        }
    }

    public String getTitle(){
        return this.label.getText();
    }

    public void setTitle(String title){
        this.label.setText(title);
    }

    public boolean wasEditedByUser() {
        return wasEdited;
    }
}
