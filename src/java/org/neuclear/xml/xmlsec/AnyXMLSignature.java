package org.neuclear.xml.xmlsec;

import org.dom4j.Element;

/**
 * This is the most general form of a XMLSignature. It doesnt check for the references it only checks to see if a
 * the signature is valid. As such this should NEVER be used in anything but applications that check for interoperabiity.
 */
public class AnyXMLSignature extends XMLSignature {
    public AnyXMLSignature(Element elem) throws XMLSecurityException, InvalidSignatureException {
        super(XMLSecTools.getSignatureElement(elem));
    }
}
