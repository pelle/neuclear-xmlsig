package org.neuclear.xml.c14;

import org.neuclear.xml.transforms.TransformerFactory;

/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Feb 8, 2003
 * Time: 9:23:01 AM
 * $Id: CanonicalizerWithoutSignature.java,v 1.4 2004/03/08 23:51:03 pelle Exp $
 * $Log: CanonicalizerWithoutSignature.java,v $
 * Revision 1.4  2004/03/08 23:51:03  pelle
 * More improvements on the XMLSignature. Now uses the Transforms properly, References properly.
 * All the major elements have been refactored to be cleaner and more correct.
 *
 * Revision 1.3  2003/11/21 04:44:30  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 * <p/>
 * Revision 1.2  2003/11/11 21:18:07  pelle
 * Further vital reshuffling.
 * org.neudist.crypto.* and org.neudist.utils.* have been moved to respective areas under org.neuclear.commons
 * org.neuclear.signers.* as well as org.neuclear.passphraseagents have been moved under org.neuclear.commons.crypto as well.
 * Did a bit of work on the Canonicalizer and changed a few other minor bits.
 * <p/>
 * Revision 1.1.1.1  2003/11/11 16:33:20  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 * <p/>
 * Revision 1.3  2003/02/21 22:48:14  pelle
 * New Test Infrastructure
 * Added test keys in src/testdata/keys
 * Modified tools to handle these keys
 * <p/>
 * Revision 1.2  2003/02/11 14:47:03  pelle
 * Added benchmarking code.
 * DigestValue is now a required part.
 * If you pass a keypair when you sign, you get the PublicKey included as a KeyInfo block within the signature.
 * <p/>
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
 */
public final class CanonicalizerWithoutSignature extends Canonicalizer {

    public CanonicalizerWithoutSignature() {
        super(ALGORITHM, XPATH_W_COMMENTS);
    }

    public static final String XPATH_W_COMMENTS = "(//. | //@* | //namespace::*| self::processing-instruction())[not(self::ds:Signature)]";

    public static final String ALGORITHM = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";

    {
        TransformerFactory.registerTransformer(ALGORITHM, CanonicalizerWithoutSignature.class);
    }

//    public boolean matches(Node node) {
//
//        return super.matches(node)&&!(node instanceof Element && ((Element)node).getQName().equals(SIGNATURE));
//    }
//    private final static QName SIGNATURE=XMLSecTools.createQName("Signature");
}
