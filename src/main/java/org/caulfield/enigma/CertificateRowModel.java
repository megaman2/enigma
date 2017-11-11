/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma;

import java.io.File;
import java.util.Date;
import org.caulfield.enigma.database.EnigmaCertificate;
import org.netbeans.swing.outline.RowModel;

/**
 *
 * @author pbakhtiari
 */
public class CertificateRowModel implements RowModel {

    public Class getColumnClass(int column) {
        switch (column) {
            case 0:
                return Integer.class;
            case 1:
                return String.class;
            case 2:
                return String.class;
            case 3:
                return String.class;
            default:
                assert false;
        }
        return null;
    }

    public int getColumnCount() {
        return 4;
    }

    public String getColumnName(int column) {
        switch (column) {
            case 0:
                return "ID";
            case 1:
                return "DATA";
            case 2:
                return "DATA";
            case 3:
                return "DATA";
            default:
                assert false;
        }
        return null;
    }

    public Object getValueFor(Object node, int column) {
        File f = (File) node;
        switch (column) {
            case 0:
                return ((EnigmaCertificate)node).getId_cert();
            case 1:
                return ((EnigmaCertificate)node).getCertname();
                  case 2:
                return ((EnigmaCertificate)node).getCN();
                  case 3:
                return ((EnigmaCertificate)node).getThumbprint();
            default:
                assert false;
        }
        return null;
    }

    public boolean isCellEditable(Object node, int column) {
        return false;
    }

    public void setValueFor(Object node, int column, Object value) {
        //do nothing, nothing is editable
    }

}
