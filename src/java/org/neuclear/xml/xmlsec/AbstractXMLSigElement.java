/* $Id: AbstractXMLSigElement.java,v 1.2 2003/11/21 04:44:31 pelle Exp $
 * $Log: AbstractXMLSigElement.java,v $
 * Revision 1.2  2003/11/21 04:44:31  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.1.1.1  2003/11/11 16:33:24  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.2  2003/02/08 18:48:37  pelle
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
 * @version $Revision: 1.2 $
 */

import org.dom4j.Element;
import org.dom4j.Namespace;
import org.neuclear.xml.AbstractElementProxy;

public abstract class AbstractXMLSigElement extends AbstractElementProxy {
    protected AbstractXMLSigElement(final String name) {
        super(name, XMLSecTools.NS_DS);
    }
//    protected AbstractXMLSigElement() {
//        ;
//    }
    protected AbstractXMLSigElement(final Element elem) throws XMLSecurityException {
        super(elem);
        if (!elem.getNamespaceURI().equalsIgnoreCase(XMLSecTools.NS_DS.getURI()))
            throw new XMLSecurityException("Element: " + elem.getQualifiedName() + " is not part of XML NS: " + XMLSecTools.NS_DS.getURI());
    }

    public final Namespace getNS() {
        return XMLSecTools.NS_DS;
    }
}
