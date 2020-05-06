/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma.analyzer;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Ender
 */
public class Scenario {

    private ArrayList<Step> steps;
    private Iterator<Step> stepsIterator;

    public Scenario() {
        steps = new ArrayList<Step>();
        stepsIterator = steps.iterator();
    }

    public ArrayList<Step> getSteps() {
        return steps;
    }

    public void addStep(Class clazz, Object obj, File param, String method) {
        steps.add(new Step(clazz, obj, param, method));
        stepsIterator = steps.iterator();
    }

    public boolean hasNextStep() {
        return stepsIterator.hasNext();
    }

    public Object runNextStep() {
        Object out = null;
        Step step = null;
        if (stepsIterator.hasNext()) {
            step = stepsIterator.next();
        } else {
            return null;
        }
        Method method = null;
        try {
            method = step.getClazz().getMethod(step.getMethod(), File.class);
            
            out = method.invoke(step.getObj(), step.getParam());
            System.out.println("====================== Invoking "+step.getMethod()+" returns:"+out);
        } catch (SecurityException | NoSuchMethodException | IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
            Logger.getLogger(Scenario.class.getName()).log(Level.SEVERE, null, ex);
        }
        return out;
    }
}
