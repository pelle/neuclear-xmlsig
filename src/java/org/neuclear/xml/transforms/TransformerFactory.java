package org.neuclear.xml.transforms;

import org.dom4j.Element;
import org.neuclear.xml.c14.Canonicalizer;
import org.neuclear.xml.c14.CanonicalizerWithComments;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;

/**
 * Created by IntelliJ IDEA.
 * User: pelleb
 * Date: Dec 20, 2002
 * Time: 1:57:02 PM
 * To change this template use Options | File Templates.
 */
public final class TransformerFactory {

    public static final Transform make(Element elem) throws XMLTransformNotFoundException{
        if (elem==null)
            throw new XMLTransformNotFoundException("The Transform element was emtpy");
        String name=elem.attributeValue("Algorithm");
        Class imp=(Class)instance().implementations.get(name);
        if (imp==null)
            throw new XMLTransformNotFoundException("The Transform: "+name+" wasnt found");
        Class params[]= new Class[] { Element.class};
        try {
            Constructor constructor=imp.getConstructor(params);
            return (Transform)constructor.newInstance(new Element[] {elem});
        } catch (NoSuchMethodException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (SecurityException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (InstantiationException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (IllegalAccessException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (InvocationTargetException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        }

        return null;
    }
    public static final Transform make(String algorithm) throws XMLTransformNotFoundException {
        Class imp=(Class)instance().implementations.get(algorithm);
        if (imp==null) {

            throw new XMLTransformNotFoundException("The Transform: "+algorithm+" wasnt found");

        }
        try {
            return (Transform)imp.newInstance();
        } catch (SecurityException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (InstantiationException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (IllegalAccessException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        }

        return null;

    }

    public static final void registerTransformer(String algorithm, Class implementation) {
        instance().implementations.put(algorithm,implementation);
    }

    private TransformerFactory () {
        implementations=new HashMap();
    }

    private static synchronized TransformerFactory instance() {
        if (singleton==null)  {
            singleton=new TransformerFactory();
            registerTransformer(DropSignatureTransform.ALGORITHM,DropSignatureTransform.class);
            registerTransformer(Canonicalizer.ALGORITHM,Canonicalizer.class);
            registerTransformer(CanonicalizerWithComments.ALGORITHM,CanonicalizerWithComments.class);
            registerTransformer(ClearTransform.ALGORITHM,ClearTransform.class);
            registerTransformer(OpaqueTransform.ALGORITHM,OpaqueTransform.class);
        }
        return singleton;
    }
    private HashMap implementations;
    private static TransformerFactory singleton;

    // This is just to make sure that they register themselves
    private static Class touch=DropSignatureTransform.class;
    {
        touch=Canonicalizer.class;
        touch=CanonicalizerWithComments.class;

    }


}
