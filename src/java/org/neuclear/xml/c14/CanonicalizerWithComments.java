package org.neuclear.xml.c14;

import org.neuclear.xml.transforms.TransformerFactory;

import java.io.Writer;

/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Feb 8, 2003
 * Time: 9:23:01 AM
 * $Id: CanonicalizerWithComments.java,v 1.1 2003/11/11 16:33:20 pelle Exp $
 * $Log: CanonicalizerWithComments.java,v $
 * Revision 1.1  2003/11/11 16:33:20  pelle
 * Initial revision
 *
 * Revision 1.1  2003/02/08 18:48:07  pelle
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
 */
public class CanonicalizerWithComments extends Canonicalizer{
    public CanonicalizerWithComments() {
    }

    public CanonicalizerWithComments(Writer writer) {
        super(writer,XPATH_W_COMMENTS);
    }
    public static final String XPATH_W_COMMENTS = "(//. | //@* | //namespace::*| self::processing-instruction()|self::comment())";

    public static final String ALGORITHM="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    {
        TransformerFactory.registerTransformer(ALGORITHM,CanonicalizerWithComments.class);
    }

}
