package org.neuclear.xml.transforms;

import org.dom4j.Element;
import org.neuclear.xml.c14.Canonicalizer;
import org.neuclear.xml.c14.CanonicalizerWithComments;

import java.util.HashMap;

/**
 * Created by IntelliJ IDEA.
 * User: pelleb
 * Date: Dec 20, 2002
 * Time: 1:57:02 PM
 * To change this template use Options | File Templates.
 */
public final class TransformerFactory {

    public static final Transform make(final Element elem) throws XMLTransformNotFoundException {
        if (elem == null)
            throw new XMLTransformNotFoundException("The Transform element was emtpy");
        final String name = elem.attributeValue("Algorithm");
        final Class imp = (Class) instance().implementations.get(name);
        if (imp == null)
            throw new XMLTransformNotFoundException("The Transform: " + name + " wasnt found");
        try {
            return (Transform) imp.newInstance();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static final Transform make(final String algorithm) throws XMLTransformNotFoundException {
        final Class imp = (Class) instance().implementations.get(algorithm);
        if (imp == null) {

            throw new XMLTransformNotFoundException("The Transform: " + algorithm + " wasnt found");

        }
        try {
            return (Transform) imp.newInstance();
        } catch (SecurityException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (InstantiationException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (IllegalAccessException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        }

        return null;

    }

    public static final void registerTransformer(final String algorithm, final Class implementation) {
        instance().implementations.put(algorithm, implementation);
    }

    private TransformerFactory() {
        implementations = new HashMap();
    }

    private static synchronized TransformerFactory instance() {
        if (singleton == null) {
            singleton = new TransformerFactory();
            registerTransformer(EnvelopedSignatureTransform.ALGORITHM, EnvelopedSignatureTransform.class);
            registerTransformer(Canonicalizer.ALGORITHM, Canonicalizer.class);
            registerTransformer(CanonicalizerWithComments.ALGORITHM, CanonicalizerWithComments.class);
            registerTransformer(ClearTransform.ALGORITHM, ClearTransform.class);
            registerTransformer(OpaqueTransform.ALGORITHM, OpaqueTransform.class);
        }
        return singleton;
    }

    private final HashMap implementations;
    private static TransformerFactory singleton;

    // This is just to make sure that they register themselves
    static {
        Class touch = EnvelopedSignatureTransform.class;
        touch = Canonicalizer.class;
        touch = CanonicalizerWithComments.class;

    }


}
