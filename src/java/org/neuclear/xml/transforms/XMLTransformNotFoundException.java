package org.neuclear.xml.transforms;


/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 21, 2003
 * Time: 4:38:57 PM
 * $Id: XMLTransformNotFoundException.java,v 1.2 2003/11/21 04:44:30 pelle Exp $
 * $Log: XMLTransformNotFoundException.java,v $
 * Revision 1.2  2003/11/21 04:44:30  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.1.1.1  2003/11/11 16:33:24  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.1  2003/01/21 22:01:43  pelle
 * Added a bunch of test cases for Transforms.
 * Also several new transforms are there.
 * I have a feeling I didn't think this through, so dont use the Transform bit yet.
 * NB. None of it is used yet by the actual signing process so dont worry.
 *
 */
import org.neuclear.xml.xmlsec.XMLSecurityException;

public final class XMLTransformNotFoundException extends XMLSecurityException {
    public XMLTransformNotFoundException(final String message) {
        super(message);
    }

    public XMLTransformNotFoundException(final String message, final Throwable t) {
        super(message, t);
    }

    public XMLTransformNotFoundException(final Throwable t) {
        super(t);
    }
}
