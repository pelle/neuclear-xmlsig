/* $Id: SOAPException.java,v 1.1 2003/11/11 16:33:23 pelle Exp $
 * $Log: SOAPException.java,v $
 * Revision 1.1  2003/11/11 16:33:23  pelle
 * Initial revision
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
 * @version $Revision: 1.1 $
 */

import org.neuclear.xml.XMLException;

public class SOAPException extends XMLException{
    public SOAPException(String message) {
        super(message);
    }

    public SOAPException(Throwable t) {
        super(t);
    }

    public SOAPException(String message, Throwable t) {
        super(message, t);
    }
}
