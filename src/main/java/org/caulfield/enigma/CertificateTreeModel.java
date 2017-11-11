/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma;

import javax.swing.tree.TreeModel;
import org.caulfield.enigma.database.EnigmaCertificate;

/**
 *
 * @author pbakhtiari
 */
public class CertificateTreeModel implements TreeModel {

    private EnigmaCertificate root;

    public CertificateTreeModel() {
        this.root = new EnigmaCertificate();
    }

    public CertificateTreeModel(EnigmaCertificate rootBone) {
        if (rootBone != null) {
            this.root = rootBone;
        } else {
            this.root = new EnigmaCertificate();
        }
    }

    public void setRoot(EnigmaCertificate rootBone) {
        this.root = rootBone;
    }

    @Override
    public void addTreeModelListener(javax.swing.event.TreeModelListener l) {
        //do nothing 
    }

    @Override
    public Object getChild(Object parent, int index) {
        EnigmaCertificate f = (EnigmaCertificate) parent;

        if (f.getChilds() == null) {
            return null;
        }
        return f.getChilds().get(index);
    }

    @Override
    public int getChildCount(Object parent) {
        EnigmaCertificate f = (EnigmaCertificate) parent;

        if (f.getChilds() == null) {
            return 0;
        }
        return f.getChilds().size();

    }

    @Override
    public int getIndexOfChild(Object parent, Object child) {
        EnigmaCertificate par = (EnigmaCertificate) parent;
        EnigmaCertificate ch = (EnigmaCertificate) child;

        if (par.getChilds() == null) {
            return 0;
        }
        return par.getChilds().indexOf(ch);
    }

    @Override
    public Object getRoot() {
        return root;
    }

    @Override
    public boolean isLeaf(Object node) {
        EnigmaCertificate f = (EnigmaCertificate) node;
        if (f.getChilds() == null) {
            return true;
        }
        return f.getChilds().isEmpty();
    }

    @Override
    public void removeTreeModelListener(javax.swing.event.TreeModelListener l) {
        //do nothing 
    }

    @Override
    public void valueForPathChanged(javax.swing.tree.TreePath path, Object newValue) {
        //do nothing 
    }
}
