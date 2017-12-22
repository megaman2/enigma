/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma;

import java.awt.Color;
import java.awt.Component;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

/**
 *
 * @author Ender
 */
public class CertificateTableCellRenderer extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table,
            Object value, boolean isSelected, boolean hasFocus, int row, int col) {

//        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);

        if (row == 1 || row == 4 || row == 5 || row == 6 || row == 7 || row == 8 || row == 9 || row == 10) {
            setHorizontalAlignment(JLabel.CENTER);
        }

        String status = (String) table.getModel().getValueAt(row, 10);
        if ("REVOKED".equals(status)) {
            setBackground(new Color(252, 252, 252));
            setForeground(new Color(230, 76, 76));
        } else {
//            setBackground(table.getBackground());
//            setForeground(table.getForeground());
        }
        return this;
    }

}
