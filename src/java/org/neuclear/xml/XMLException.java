/* $Id: XMLException.java,v 1.1 2003/11/11 16:33:20 pelle Exp $
 * $Log: XMLException.java,v $
 * Revision 1.1  2003/11/11 16:33:20  pelle
 * Initial revision
 *
 * Revision 1.2  2003/10/21 22:30:33  pelle
 * Renamed NeudistException to NeuClearException and moved it to org.neuclear.commons where it makes more sense.
 * Unhooked the XMLException in the xmlsig library from NeuClearException to make all of its exceptions an independent hierarchy.
 * Obviously had to perform many changes throughout the code to support these changes.
 *
 * Revision 1.1  2003/01/18 18:12:31  pelle
 * First Independent commit of the Independent XML-Signature API for NeuDist.
 *
 * Revision 1.2  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 */
package org.neuclear.xml;
/**
 * @author pelleb
 * @version $Revision: 1.1 $
 */

import org.neuclear.commons.NeuClearException;

public class XMLException extends Exception {
    public XMLException(String message) {
        super(message);
    }

    public XMLException(Throwable t) {
        super(t);
    }

    public XMLException(String message, Throwable t) {
        super(message, t);
    }
}
