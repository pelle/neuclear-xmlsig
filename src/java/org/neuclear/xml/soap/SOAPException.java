/* $Id: SOAPException.java,v 1.2 2003/11/21 04:44:30 pelle Exp $
 * $Log: SOAPException.java,v $
 * Revision 1.2  2003/11/21 04:44:30  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.1.1.1  2003/11/11 16:33:23  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.1  2003/01/18 18:12:31  pelle
 * First Independent commit of the Independent XML-Signature API for NeuDist.
 *
 * Revision 1.2  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 */
package org.neuclear.xml.soap;
/**
 * @author pelleb
 * @version $Revision: 1.2 $
 */

import org.neuclear.xml.XMLException;

public final class SOAPException extends XMLException{
    public SOAPException(final String message) {
        super(message);
    }

    public SOAPException(final Throwable t) {
        super(t);
    }

    public SOAPException(final String message, final Throwable t) {
        super(message, t);
    }
}
