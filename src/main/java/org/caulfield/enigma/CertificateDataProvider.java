/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma;

import java.io.File;
import javax.swing.ImageIcon;
import javax.swing.UIManager;
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
        EnigmaCertificate f = (EnigmaCertificate) o;
        if (!f.isUser() && !f.isSub()) {
            return UIManager.getColor("controlShadow");
        }
        return null;
    }

    public javax.swing.Icon getIcon(Object o) {
        ImageIcon icon = null;
        if (((EnigmaCertificate) o).isRoot()) {
            icon = new ImageIcon(getClass().getResource("/AC.png"));
        } else if (((EnigmaCertificate) o).isSub()) {
            icon = new ImageIcon(getClass().getResource("/sub.png"));
        } else if (((EnigmaCertificate) o).isUser()) {
            icon = new ImageIcon(getClass().getResource("/usercert.png"));
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
