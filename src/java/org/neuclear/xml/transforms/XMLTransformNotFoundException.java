package org.neuclear.xml.transforms;


/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 21, 2003
 * Time: 4:38:57 PM
 * $Id: XMLTransformNotFoundException.java,v 1.1 2003/11/11 16:33:24 pelle Exp $
 * $Log: XMLTransformNotFoundException.java,v $
 * Revision 1.1  2003/11/11 16:33:24  pelle
 * Initial revision
 *
 * Revision 1.1  2003/01/21 22:01:43  pelle
 * Added a bunch of test cases for Transforms.
 * Also several new transforms are there.
 * I have a feeling I didn't think this through, so dont use the Transform bit yet.
 * NB. None of it is used yet by the actual signing process so dont worry.
 *
 */
import org.neuclear.xml.xmlsec.XMLSecurityException;

public class XMLTransformNotFoundException extends XMLSecurityException {
    public XMLTransformNotFoundException(String message) {
        super(message);
    }

    public XMLTransformNotFoundException(String message, Throwable t) {
        super(message, t);
    }

    public XMLTransformNotFoundException(Throwable t) {
        super(t);
    }
}
