/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.database;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Ender
 */
public class EnigmaCertificate {

    //CREATE TABLE CERTIFICATES (ID_CERT INTEGER PRIMARY KEY, CERTNAME VARCHAR(200),CN VARCHAR(200),ALGO VARCHAR(64),CERTFILE BLOB,SHA256  VARCHAR(256),THUMBPRINT  VARCHAR(256),ID_ISSUER_CERT INTEGER, ID_PRIVATEKEY INTEGER);
    private Integer id_cert;
    private String certname;
    private String CN;
    private String algo;
    private InputStream certfile;
    private String SHA256;
    private String thumbprint;
    private Integer id_issuer_cert;
    private Integer id_private_key;
    private Integer certtype;
    private List<EnigmaCertificate> childs;

    public EnigmaCertificate() {
        childs = new ArrayList<>();
    }

    public boolean isRoot() {
        return certtype.intValue() == 1;
    }

    public boolean isSub() {
        return certtype.intValue() == 2;
    }

    public boolean isUser() {
        return certtype.intValue() == 3;
    }

    public boolean hasChilds() {
        return !childs.isEmpty();
    }

    /**
     * @return the id_cert
     */
    public Integer getId_cert() {
        return id_cert;
    }

    /**
     * @param id_cert the id_cert to set
     */
    public void setId_cert(Integer id_cert) {
        this.id_cert = id_cert;
    }

    /**
     * @return the certname
     */
    public String getCertname() {
        return certname;
    }

    /**
     * @param certname the certname to set
     */
    public void setCertname(String certname) {
        this.certname = certname;
    }

    /**
     * @return the CN
     */
    public String getCN() {
        return CN;
    }

    /**
     * @param CN the CN to set
     */
    public void setCN(String CN) {
        this.CN = CN;
    }

    /**
     * @return the algo
     */
    public String getAlgo() {
        return algo;
    }

    /**
     * @param algo the algo to set
     */
    public void setAlgo(String algo) {
        this.algo = algo;
    }

    /**
     * @return the certfile
     */
    public InputStream getCertfile() {
        return certfile;
    }

    /**
     * @param certfile the certfile to set
     */
    public void setCertfile(InputStream certfile) {
        this.certfile = certfile;
    }

    /**
     * @return the thumbprint
     */
    public String getThumbprint() {
        return thumbprint;
    }

    /**
     * @param thumbprint the thumbprint to set
     */
    public void setThumbprint(String thumbprint) {
        this.thumbprint = thumbprint;
    }

    /**
     * @return the id_issuer_cert
     */
    public Integer getId_issuer_cert() {
        return id_issuer_cert;
    }

    /**
     * @param id_issuer_cert the id_issuer_cert to set
     */
    public void setId_issuer_cert(Integer id_issuer_cert) {
        this.id_issuer_cert = id_issuer_cert;
    }

    /**
     * @return the id_private_key
     */
    public Integer getId_private_key() {
        return id_private_key;
    }

    /**
     * @param id_private_key the id_private_key to set
     */
    public void setId_private_key(Integer id_private_key) {
        this.id_private_key = id_private_key;
    }

    /**
     * @return the childs
     */
    public List<EnigmaCertificate> getChilds() {
        return childs;
    }

    /**
     * @param childs the childs to set
     */
    public void setChilds(List<EnigmaCertificate> childs) {
        this.childs = childs;
    }

    /**
     * @return the SHA256
     */
    public String getSHA256() {
        return SHA256;
    }

    /**
     * @param SHA256 the SHA256 to set
     */
    public void setSHA256(String SHA256) {
        this.SHA256 = SHA256;
    }

    /**
     * @return the certtype
     */
    public Integer getCerttype() {
        return certtype;
    }

    /**
     * @param certtype the certtype to set
     */
    public void setCerttype(Integer certtype) {
        this.certtype = certtype;
    }

}
