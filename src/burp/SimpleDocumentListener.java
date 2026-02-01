package burp;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

final class SimpleDocumentListener implements DocumentListener {
    private final Runnable onChange;

    SimpleDocumentListener(Runnable onChange) {
        this.onChange = onChange;
    }

    @Override
    public void insertUpdate(DocumentEvent e) {
        if (onChange != null) {
            onChange.run();
        }
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
        if (onChange != null) {
            onChange.run();
        }
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
        if (onChange != null) {
            onChange.run();
        }
    }
}
