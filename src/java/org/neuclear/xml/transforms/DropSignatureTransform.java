package org.neuclear.xml.transforms;
/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 27, 2003
 * Time: 10:02:07 AM
 * $Id: DropSignatureTransform.java,v 1.2 2003/11/21 04:44:30 pelle Exp $
 * $Log: DropSignatureTransform.java,v $
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
 * Revision 1.3  2003/02/22 16:54:29  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.2  2003/02/11 14:50:09  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
 *
 * Revision 1.1  2003/02/01 01:48:17  pelle
 * Fixed the XPath Transform.
 * Has the beginning of a processing framework for the Reference class.
 *
 */

import org.dom4j.*;
import org.neuclear.xml.xmlsec.XMLSecTools;
import org.neuclear.xml.xmlsec.XMLSecurityException;

import java.util.ListIterator;

public final class DropSignatureTransform extends Transform{
    public DropSignatureTransform() {
        super(ALGORITHM);
    }

    public DropSignatureTransform(final Element elem) throws XMLSecurityException {
        super(elem);
    }


    public final Object transformNode(final Object in) {
        if (in instanceof Document){
            transformNode(((Document)in).getRootElement());
        } else if (in instanceof Element){
            final ListIterator iter=((Branch)in).content().listIterator();
            while(iter.hasNext()) {
                final Node node=(Node)iter.next();
                if ((node instanceof Element)&&(((Element)node).getQName().equals(subject)) )
                    iter.remove();
//                else if (node instanceof Branch) {
//                    transformNode(in);
//                }
            }
        }
      return in;
    }
    private static final QName subject=XMLSecTools.createQName("Signature");
    public static final String ALGORITHM="http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    {
        TransformerFactory.registerTransformer(ALGORITHM,DropSignatureTransform.class);
    }
}
