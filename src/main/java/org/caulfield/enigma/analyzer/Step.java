/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.analyzer;

import java.io.File;

/**
 *
 * @author Ender
 */
class Step<T> {

    private Class clazz;
    private Object obj;
    private File param;
    private String method;

    public Step(Class clazz, Object obj, File param, String method) {
        this.clazz = clazz;
        this.obj = obj;
        this.param = param;
        this.method = method;
    }

    public File getParam() {
        return param;
    }

    public Object getObj() {
        return obj;
    }

    public String getMethod() {
        return method;
    }

    public Class getClazz() {
        return clazz;
    }

}
