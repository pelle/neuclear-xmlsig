/*
 * Created by IntelliJ IDEA.
 * User: pelleb
 * Date: Sep 10, 2002
 * Time: 11:46:36 AM
 * To change template for new interface use 
 * Code Style | Class Templates options (Tools | IDE Options).
 */
package org.neuclear.xml;

import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;

public interface ElementProxy {
    public Element getElement();
    public QName getQName();
    public String getTagName();
    public Namespace getNS();


    static Namespace XMLNS= DocumentHelper.createNamespace("xmlns","http://www.w3.org/XML/1998/namespace");
    /**
     * Generates a textual XML Representation of an object.
     * @return XML as text
     * @throws XMLException
     */
    String asXML() throws XMLException;

    /**
     * Canonicalizes object's XML Representation
     * @return byte array containing the Canonicalized Object
     * @throws XMLException
     */
    byte[] canonicalize() throws XMLException;
}
