/* $Id: XMLSecurityException.java,v 1.1 2003/11/11 16:33:28 pelle Exp $
 * $Log: XMLSecurityException.java,v $
 * Revision 1.1  2003/11/11 16:33:28  pelle
 * Initial revision
 *
 * Revision 1.2  2003/02/08 18:48:38  pelle
 * The Signature phase has been rewritten.
 * There now is a new Class called QuickEmbeddedSignature which is more in line with my original idea for this library.
 * It simply has a template of the xml and signs it in a standard way.
 * The original XMLSignature class is still used for verification and will in the future handle more thoroughly
 * all the various flavours of XMLSig.
 * XMLSecTools has got different flavours of canonicalize now. Including one where you can pass it a Canonicaliser to use.
 * Of the new Canonicalizer's are CanonicalizerWithComments, which I accidently left out of the last commit.
 * And CanonicalizerWithoutSignature which leaves out the Signature in the Canonicalization phase and is thus
 * a lot more efficient than the previous approach.
 *
 * Revision 1.1  2003/01/18 18:12:32  pelle
 * First Independent commit of the Independent XML-Signature API for NeuDist.
 *
 * Revision 1.2  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 */
package org.neuclear.xml.xmlsec;

/**
 * @author pelleb
 * @version $Revision: 1.1 $
 */

import org.neuclear.xml.XMLException;

public class XMLSecurityException extends XMLException {
    public XMLSecurityException(String message) {
        super(message);
    }

    public XMLSecurityException(Throwable t) {
        super(t);
    }

    public XMLSecurityException(String message, Throwable t) {
        super(message, t);
    }
}
