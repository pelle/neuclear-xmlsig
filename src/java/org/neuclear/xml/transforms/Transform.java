package org.neuclear.xml.transforms;

import org.dom4j.Element;
import org.neuclear.xml.xmlsec.AbstractXMLSigElement;
import org.neuclear.xml.xmlsec.XMLSecurityException;

/**
 * Created by IntelliJ IDEA.
 * User: pelleb
 * Date: Dec 20, 2002
 * Time: 1:48:41 PM
 * To change this template use Options | File Templates.
 */
public abstract class Transform extends AbstractXMLSigElement {
    public Transform(final String algorithm) {
        super(TAG_NAME);
        createAttribute("Algorithm", algorithm);
    }

    public Transform(final Element elem) throws XMLSecurityException {
        super(elem);
    }

//    public abstract Node transformNode(Node in);
    public abstract Object transformNode(Object in);

    private static final String TAG_NAME = "Transform";
}
