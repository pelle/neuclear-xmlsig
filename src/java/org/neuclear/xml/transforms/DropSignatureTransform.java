package org.neuclear.xml.transforms;
/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 27, 2003
 * Time: 10:02:07 AM
 * $Id: DropSignatureTransform.java,v 1.1 2003/11/11 16:33:24 pelle Exp $
 * $Log: DropSignatureTransform.java,v $
 * Revision 1.1  2003/11/11 16:33:24  pelle
 * Initial revision
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

public class DropSignatureTransform extends Transform{
    public DropSignatureTransform() {
        super(ALGORITHM);
    }

    public DropSignatureTransform(Element elem) throws XMLSecurityException {
        super(elem);
    }


    public Object transformNode(Object in) {
        if (in instanceof Document){
            transformNode(((Document)in).getRootElement());
        } else if (in instanceof Element){
            ListIterator iter=((Branch)in).content().listIterator();
            while(iter.hasNext()) {
                Node node=(Node)iter.next();
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
