/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma;

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
            case 4:
                return Integer.class;
            case 5:
                return Date.class;
            case 6:
                return String.class;
            case 7:
                return String.class;
            case 8:
                return String.class;
            case 9:
                return Date.class;
            default:
                assert false;
        }
        return null;
    }

    public int getColumnCount() {
        return 10;
    }

    public String getColumnName(int column) {
        switch (column) {
            case 0:
                return "ID";
            case 1:
                return "CN";
            case 2:
                return "Thumbprint";
            case 3:
                return "Algo";
            case 4:
                return "ID Private Key";
            case 5:
                return "Expiry Date";
            case 6:
                return "Type";
            case 7:
                return "Serial";
            case 8:
                return "AC Serial Cursor";
            case 9:
                return "Last CRL update";
            default:
                assert false;
        }
        return null;
    }

    public Object getValueFor(Object node, int column) {
        EnigmaCertificate f = (EnigmaCertificate) node;
        switch (column) {
            case 0:
                return ((EnigmaCertificate) node).getId_cert();
            case 1:
                return ((EnigmaCertificate) node).getCN();
            case 2:
                return ((EnigmaCertificate) node).getThumbprint();
            case 3:
                return ((EnigmaCertificate) node).getAlgo();
            case 4:
                return ((EnigmaCertificate) node).getId_private_key();
            case 5:
                return ((EnigmaCertificate) node).getExpiryDate();
            case 6:
                if (((EnigmaCertificate) node).isUser()) {
                    return "USER";
                } else if (((EnigmaCertificate) node).isSub()) {
                    return "SUB";
                } else if (((EnigmaCertificate) node).isRoot()) {
                    return "ROOT";
                }
            case 7:
                return ((EnigmaCertificate) node).getSerial();
            case 8:
                return ((EnigmaCertificate) node).getAcserialcursor();
            case 9:
                return ((EnigmaCertificate) node).getLastcrlupdate();
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
