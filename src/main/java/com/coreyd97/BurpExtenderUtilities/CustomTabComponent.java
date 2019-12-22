package com.coreyd97.BurpExtenderUtilities;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.*;
import java.util.function.Consumer;

public class CustomTabComponent extends JPanel {

    private JLabel indexLabel;
    private JLabel titleLabel;
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

    public CustomTabComponent(int index, String title,
                              boolean showIndex,
                              boolean isEditable, Consumer<String> onTitleChanged,
                              boolean isRemovable, Consumer<Void> onRemovePressed){
        super(new BorderLayout());
        this.setOpaque(false);
        this.index = index;
        this.showIndex = showIndex;
        this.isEditable = isEditable;
        this.onTitleChanged = onTitleChanged;
        this.isRemovable = isRemovable;
        this.onRemovePressed = onRemovePressed;
        this.wasEdited = false;

        if(this.showIndex){
            indexLabel = new JLabel(index + ": ");
            this.add(indexLabel, BorderLayout.WEST);
        }

        editableField = new JTextField(title);
        editableFieldBorder = editableField.getBorder();
        editableField.setBorder(null);
        editableField.setOpaque(false);
        editableField.setBackground(new Color(0,0,0,0));

//        add(editableField);
        titleLabel = new JLabel(title);
        add(titleLabel, BorderLayout.CENTER);

        if(this.isEditable) {
            this.editClickListener = new EditClickListener();
            this.addMouseListener(editClickListener);

            this.addFocusListener(new FocusAdapter() {
                @Override
                public void focusLost(FocusEvent e) {
                    endEditLabel();
                }
            });

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
//            add(Box.createHorizontalStrut(5));
            add(removeTabButton, BorderLayout.EAST);
        }

        revalidate();
        repaint();

    }

    private void editLabel(){
        this.remove(titleLabel);
        originalTitle = titleLabel.getText();
        editableField.setText(originalTitle);
        editableField.setBorder(editableFieldBorder);
        editableField.requestFocus();
        this.add(editableField, BorderLayout.CENTER);
        this.revalidate();
        this.repaint();
    }

    private void endEditLabel(){
        this.remove(editableField);
        editableField.setBorder(null);
        if(!editableField.getText().equals(originalTitle)){
            wasEdited = true;
        }
        if(this.onTitleChanged != null)
            this.onTitleChanged.accept(editableField.getText());
        titleLabel.setText(editableField.getText());
        this.add(titleLabel, BorderLayout.CENTER);
        this.revalidate();
        this.repaint();
    }

    private class EditClickListener extends MouseAdapter {
        @Override
        public void mousePressed(MouseEvent e) {
            handleEvent(e);
        }

        @Override
        public void mouseReleased(MouseEvent e) {
            handleEvent(e);
        }

        @Override
        public void mouseClicked(MouseEvent e) {
            handleEvent(e);
        }

        private void handleEvent(MouseEvent mouseEvent){
            if(SwingUtilities.isLeftMouseButton(mouseEvent)) {
                if (mouseEvent.getClickCount() > 1) {
                    editLabel();
                }
            }

            //For some reason, Custom tab components with mouselisteners
            //do not bubble up to select the tab. This kind of fixes that.
            JTabbedPane parent = (JTabbedPane) CustomTabComponent.this.getParent().getParent();
            int tabIndex = parent.indexOfTabComponent(CustomTabComponent.this);
            parent.setSelectedIndex(tabIndex);
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
        this.titleLabel.setText(title);
        this.revalidate();
        this.repaint();
    }

    public boolean wasEditedByUser() {
        return wasEdited;
    }
}
