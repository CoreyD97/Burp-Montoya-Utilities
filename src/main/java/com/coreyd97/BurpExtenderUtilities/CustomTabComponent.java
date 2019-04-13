package com.coreyd97.BurpExtenderUtilities;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.*;
import java.util.function.Consumer;

public class CustomTabComponent extends JPanel {

    private final JTabbedPane parentPane;
    private JLabel indexLabel;
    private JTextField editableField;
    private Border editableFieldBorder;
    private JButton removeTabButton;

    private int index;
    private boolean showIndex;
    private boolean isEditable;
    private Consumer<String> onTitleChanged;
    private boolean isRemovable;
    private Consumer<Void> onRemovePressed;

    private EditClickListener editClickListener;

    private String originalTitle;
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

        editableField = new JTextField(title);
        editableFieldBorder = editableField.getBorder();
        editableField.setBorder(null);
        editableField.setOpaque(false);
        editableField.setBackground(new Color(0,0,0,0));
        add(editableField);

        if(this.isEditable) {
            this.editClickListener = new EditClickListener();

            if(this.showIndex){
                indexLabel.addMouseListener(editClickListener);
            }
            editableField.addMouseListener(editClickListener);
            this.addMouseListener(editClickListener);

            editableField.addFocusListener(new FocusAdapter() {
                @Override
                public void focusLost(FocusEvent focusEvent) {
                    endEditLabel();
                }
            });

            editableField.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent keyEvent) {
                    if(keyEvent.getExtendedKeyCode() == KeyEvent.VK_ENTER){
                        endEditLabel();
                    }
                }
            });
        }

        if(this.isRemovable) {
            removeTabButton = new JButton("x");
            removeTabButton.setFont(removeTabButton.getFont().deriveFont(10F));
            removeTabButton.addActionListener(actionEvent -> {
                if(this.onRemovePressed != null)
                    this.onRemovePressed.accept(null);
            });
            removeTabButton.setPreferredSize(new Dimension(20,20));
            removeTabButton.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
            removeTabButton.setBackground(new Color(0,0,0,0));
            add(Box.createHorizontalStrut(5));
            add(removeTabButton);
        }

        revalidate();
        repaint();

    }

    private void editLabel(){
        originalTitle = editableField.getText();
        editableField.setEditable(true);
        editableField.setBorder(editableFieldBorder);
//        editableField.setCaretPosition(0);
    }

    private void endEditLabel(){
        editableField.setBorder(null);
        if(!editableField.getText().equals(originalTitle)){
            wasEdited = true;
        }
        if(this.onTitleChanged != null)
            this.onTitleChanged.accept(editableField.getText());
        editableField.setEditable(false);
        editableField.setSelectionStart(0);
        editableField.setSelectionEnd(0);
        this.requestFocusInWindow();
    }


    private class EditClickListener extends MouseAdapter {
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
        return this.editableField.getText();
    }

    public void setTitle(String title){
        this.editableField.setText(title);
    }

    public boolean wasEditedByUser() {
        return wasEdited;
    }
}
