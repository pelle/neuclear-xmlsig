package org.neuclear.xml.xmlsec;

/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Feb 8, 2003
 * Time: 12:15:24 PM
 * $Id: QuickEmbeddedSignature.java,v 1.8 2004/01/14 06:42:38 pelle Exp $
 * $Log: QuickEmbeddedSignature.java,v $
 * Revision 1.8  2004/01/14 06:42:38  pelle
 * Got rid of the verifyXXX() methods
 *
 * Revision 1.7  2004/01/13 23:37:59  pelle
 * Refactoring parts of the core of XMLSignature. There shouldnt be any real API changes.
 *
 * Revision 1.6  2004/01/10 00:02:02  pelle
 * Implemented new Schema for Transfer*
 * Working on it for Exchange*, so far all Receipts are implemented.
 * Added SignedNamedDocument which is a generic SignedNamedObject that works with all Signed XML.
 * Changed SignedNamedObject.getDigest() from byte array to String.
 * The whole malarchy in neuclear-pay does not build yet. The refactoring is a big job, but getting there.
 *
 * Revision 1.5  2004/01/07 23:11:51  pelle
 * XMLSig now has various added features:
 * -  KeyInfo supports X509v3 (untested)
 * -  KeyInfo supports KeyName
 * -  When creating a XMLSignature and signing it with a Signer, it adds the alias to the KeyName
 * Added KeyResolver interface and KeyResolverFactory Class. At the moment no implementations.
 *
 * Revision 1.4  2003/12/19 18:03:07  pelle
 * Revamped a lot of exception handling throughout the framework, it has been simplified in most places:
 * - For most cases the main exception to worry about now is InvalidNamedObjectException.
 * - Most lowerlevel exception that cant be handled meaningful are now wrapped in the LowLevelException, a
 *   runtime exception.
 * - Source and Store patterns each now have their own exceptions that generalizes the various physical
 *   exceptions that can happen in that area.
 *
 * Revision 1.3  2003/11/21 04:44:31  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.2  2003/11/11 21:18:07  pelle
 * Further vital reshuffling.
 * org.neudist.crypto.* and org.neudist.utils.* have been moved to respective areas under org.neuclear.commons
 * org.neuclear.signers.* as well as org.neuclear.passphraseagents have been moved under org.neuclear.commons.crypto as well.
 * Did a bit of work on the Canonicalizer and changed a few other minor bits.
 *
 * Revision 1.1.1.1  2003/11/11 16:33:28  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.12  2003/11/08 22:21:17  pelle
 * Fixed a few things with regards to the SOAPTools class.
 *
 * Revision 1.11  2003/11/08 20:27:02  pelle
 * Updated the Signer interface to return a key type to be used for XML SignatureInfo. Thus we now support DSA sigs yet again.
 *
 * Revision 1.10  2003/10/29 21:15:53  pelle
 * Refactored the whole signing process. Now we have an interface called Signer which is the old SignerStore.
 * To use it you pass a byte array and an alias. The sign method then returns the signature.
 * If a Signer needs a passphrase it uses a PassPhraseAgent to present a dialogue box, read it from a command line etc.
 * This new Signer pattern allows us to use secure signing hardware such as N-Cipher in the future for server applications as well
 * as SmartCards for end user applications.
 *
 * Revision 1.9  2003/02/24 03:26:30  pelle
 * XMLSignature class has been tested as working for Enveloped Signatures.
 * It is still failing verification on home grown Enveloping Signatures.
 * It failes while checking reference validity. This means there is something strange about the Digest is initially
 * calculated for Enveloping signatures.
 *
 * Revision 1.8  2003/02/24 00:41:07  pelle
 * Cleaned up a lot of code for new fixed processing model.
 * It all still work as before, but will be easier to modify the Reference processing model which is the only
 * main thing todo besides X509 and HMAC-SHA1 support.
 *
 * Revision 1.7  2003/02/23 23:21:46  pelle
 * Yeah. We figured it out. We now have interop.
 * Granted not on all features as yet, but definitely on simple signatures.
 * I'm checking in Ramses' fix to QuickEmbeddedSignature and my fixes to the verification process.
 *
 * Revision 1.6  2003/02/22 16:54:30  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.5  2003/02/20 13:26:42  pelle
 * Adding all of the modification from Rams?s Morales ramses@computer.org to support DSASHA1 Signatures
 * Thanks Rams?s good work.
 * So this means there is now support for:
 * - DSA KeyInfo blocks
 * - DSA Key Generation within CryptoTools
 * - Signing using DSASHA1
 *
 * Revision 1.4  2003/02/11 14:50:24  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
 *
 * Revision 1.3  2003/02/08 20:55:08  pelle
 * Some documentation changes.
 * Major reorganization of code. The code is slowly being cleaned up in such a way that we can
 * get rid of the org.neuclear.utils package and split out the org.neuclear.xml.soap package.
 * Got rid of tons of unnecessary dependencies.
 *
 * Revision 1.2  2003/02/08 19:11:10  pelle
 * Cleaned stuff up a bit.
 *
 * Revision 1.1  2003/02/08 18:48:37  pelle
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

import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.neuclear.commons.crypto.CryptoException;
import org.neuclear.commons.crypto.CryptoTools;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.PublicKeySource;
import org.neuclear.commons.crypto.signers.Signer;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;

/**
 * This a class to quickly create NeuDist format standard signatures
 */
public final class QuickEmbeddedSignature extends XMLSignature {
    public QuickEmbeddedSignature(final KeyPair keypair, final Element root) throws XMLSecurityException, CryptoException, InvalidSignatureException {
        this(keypair.getPrivate(), root);
        final Element sig = getElement();
        final KeyInfo key = new KeyInfo(keypair.getPublic());
        sig.add(key.getElement());
    }

    public QuickEmbeddedSignature(final PrivateKey key, final Element root) throws XMLSecurityException, CryptoException, InvalidSignatureException {
        super(getSignatureElement(root, key));
        final Element sig = getElement();

//        getSi().getReference().setDigest();

        final byte[] canonicalizedSignedInfo = XMLSecTools.canonicalize(sig.element("SignedInfo"));
        sig.add(XMLSecTools.base64ToElement("SignatureValue", CryptoTools.sign(key, canonicalizedSignedInfo)));
    }

    public QuickEmbeddedSignature(final String name, final Signer signer, final Element root) throws XMLSecurityException, UserCancellationException, NonExistingSignerException, InvalidSignatureException {
        super(getSignatureElement(root,signer.getKeyType(name)));
        final Element sig = getElement();

//        getSi().getReference().setDigest();
        if (signer instanceof PublicKeySource){
            final KeyInfo key = new KeyInfo(((PublicKeySource)signer).getPublicKey(name),name);
            sig.add(key.getElement());
        } else
            addElement(new KeyInfo(name)); // Add the signers name

        final byte[] canonicalizedSignedInfo = XMLSecTools.canonicalize(sig.element("SignedInfo"));
        sig.add(XMLSecTools.base64ToElement("SignatureValue", signer.sign(name, canonicalizedSignedInfo)));
    }


    private synchronized static Element getRSASigElement(final Element root) throws DocumentException {
        if (SIGNATURETEMPLATE == null)
            SIGNATURETEMPLATE = DocumentHelper.parseText(SIGNATURETEMPLATE_TEXT).getRootElement();
        final Element sig = SIGNATURETEMPLATE.createCopy();
        root.add(sig);
        return sig;
    }

    //overloading, because maybe there is another class calling the original static method
    private static Element getSignatureElement(final Element root, final PrivateKey key) throws XMLSecurityException {
        if (key instanceof RSAPrivateKey)
            return getSignatureElement(root,SignatureInfo.SIG_ALG_RSA);
        if (key instanceof DSAPrivateKey)
            return getSignatureElement(root,SignatureInfo.SIG_ALG_DSA);
        throw new XMLSecurityException("We only handle RSA or DSA keys not: "+key.getClass().getName());
    }
    //overloading, because maybe there is another class calling the original static method
    private static Element getSignatureElement(final Element root, final int keytype) throws XMLSecurityException {
        final Element signatureElement = null;
        try {
            if (keytype == SignatureInfo.SIG_ALG_RSA)
                return getRSASigElement(root);
            if (keytype == SignatureInfo.SIG_ALG_DSA)
                return getDSASigElement(root);
            return null;

        } catch (DocumentException e) {
            throw new XMLSecurityException(e);
        }
    }

    private synchronized static Element getDSASigElement(final Element root) throws DocumentException {
        final Element signatureElement;
        if (DSASIGNATURETEMPLATE == null)
            DSASIGNATURETEMPLATE =
                    DocumentHelper.parseText(DSASIGNATURETEMPLATE_TEXT).getRootElement();
        signatureElement = DSASIGNATURETEMPLATE.createCopy();
        root.add(signatureElement);
        return signatureElement;
    }

    private static Element SIGNATURETEMPLATE;
    private static final String SIGNATURETEMPLATE_TEXT = "\n<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
            "\n<ds:SignedInfo>" +
            "\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>" +
            "\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>" +
            "\n<ds:Reference URI=\"\">" +
            "\n<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" +
            "\n</ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
            "\n</ds:Reference>" +
            "\n</ds:SignedInfo>\n</ds:Signature>";

    private static Element DSASIGNATURETEMPLATE;
    private static final String DSASIGNATURETEMPLATE_TEXT = "\n<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
            "\n<ds:SignedInfo>" +
            "\n<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>" +
            "\n<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#dsa-sha1\"/>" +
            "\n<ds:Reference URI=\"\">" +
            "\n<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" +
            "\n</ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>" +
            "\n</ds:Reference>" +
            "\n</ds:SignedInfo>\n</ds:Signature>";


   /* public static void main(final String[] args) {
        try {
            final KeyPair kp = CryptoTools.createKeyPair();
//            KeyInfo keyinfo=new KeyInfo(kp.getPublic());
            Document doc = DocumentHelper.parseText("<test>One Two<test2/></test>");
            final XMLSignature xmlsig = new QuickEmbeddedSignature(kp, doc.getRootElement(), "uri:test");
            doc.getRootElement().add(xmlsig.getElement());
            System.out.println(doc.asXML());
            System.out.println("Starting benchmarks");
            long start = new Date().getTime();
            for (int i = 0; i < 1000; i++) {
                doc = DocumentHelper.parseText("<test>One Two<test2/></test>");
                XMLSecTools.signElement("uri:test", doc.getRootElement(), kp.getPrivate());
            }
            long end = new Date().getTime();
            System.out.println("1000 signatures took " + (end - start) + "ms or " + (end - start) / 1000 + "ms per signature");
            final String signed = doc.asXML();
            start = new Date().getTime();
            for (int i = 0; i < 1000; i++) {
                doc = DocumentHelper.parseText(signed);
                XMLSecTools.verifySignature(doc.getRootElement(), kp.getPublic());
            }
            end = new Date().getTime();
            System.out.println("1000 verifies took " + (end - start) + "ms or " + (end - start) / 1000 + "ms per signature");
        } catch (DocumentException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (XMLSecurityException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (CryptoException e) {
            e.printStackTrace();  //TODO Handle exception
        }
    }
*/
}
