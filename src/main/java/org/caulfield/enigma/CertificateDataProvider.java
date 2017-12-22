/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma;

import java.awt.Color;
import javax.swing.ImageIcon;
import org.caulfield.enigma.database.EnigmaCertificate;
import org.netbeans.swing.outline.RenderDataProvider;

/**
 *
 * @author pbakhtiari
 */
public class CertificateDataProvider implements RenderDataProvider {

    public java.awt.Color getBackground(Object o) {
        return null;
    }

    public String getDisplayName(Object o) {
        return ((EnigmaCertificate) o).getCertname();
    }

    public java.awt.Color getForeground(Object o) {
        Color c = null;
        EnigmaCertificate f = (EnigmaCertificate) o;
        if (f.isRoot()) {
            c = new Color(0, 0, 0);
        } else if (f.isSub()) {
            c = new Color(37, 44, 36);
        } else if (f.isUser()) {
            c = new Color(67, 116, 62);
        }
        if ("REVOKED".equals(f.getStatus())) {
            c = new Color(230, 76, 76);
        }
        return c;
    }

    public javax.swing.Icon getIcon(Object o) {
        ImageIcon icon = null;
        EnigmaCertificate f = (EnigmaCertificate) o;
        if (f.isRoot()) {
            icon = new ImageIcon(getClass().getResource("/AC.png"));
        } else if (f.isSub()) {
            icon = new ImageIcon(getClass().getResource("/sub.png"));
        } else if (f.isUser()) {
            icon = new ImageIcon(getClass().getResource("/usercert.png"));
        }
        if ("REVOKED".equals(f.getStatus())) {
            icon = new ImageIcon(getClass().getResource("/revoked.png"));
        }
        return icon;
    }

    public String getTooltipText(Object o) {
        return ((EnigmaCertificate) o).getCN();
    }

    public boolean isHtmlDisplayName(Object o) {
        return false;
    }

}
