/* $Id: SignedInfo.java,v 1.5 2004/03/19 22:21:51 pelle Exp $
 * $Log: SignedInfo.java,v $
 * Revision 1.5  2004/03/19 22:21:51  pelle
 * Changes in the XMLSignature class, which is now Abstract there are currently 3 implementations for:
 * - Enveloped
 * - DataObjects - (Enveloping)
 * - Any for interop testing mainly.
 *
 * Revision 1.4  2004/03/18 21:31:33  pelle
 * Some fixups in SignedInfo
 *
 * Revision 1.3  2004/03/08 23:51:03  pelle
 * More improvements on the XMLSignature. Now uses the Transforms properly, References properly.
 * All the major elements have been refactored to be cleaner and more correct.
 *
 * Revision 1.2  2004/03/05 23:47:17  pelle
 * Attempting to make Reference and SignedInfo more compliant with the standard.
 * SignedInfo can now contain more than one reference.
 * Reference is on the way to becoming more flexible and two support more than one transform.
 * I am adding Crypto Channels to commons to help this out and to hopefully speed things up as well.
 *
 * Revision 1.1  2004/03/02 23:30:43  pelle
 * Renamed SignatureInfo to SignedInfo as that is the name of the Element.
 * Made some changes in the Canonicalizer to make all the output verify in Aleksey's xmlsec library.
 * Unfortunately this breaks example 3 of merlin-eight's canonicalization interop tests, because dom4j afaik
 * can't tell the difference between <test/> and <test xmlns=""/>.
 * Changed XMLSignature it is now has less repeated code.
 *
 * Revision 1.6  2004/01/14 06:42:38  pelle
 * Got rid of the verifyXXX() methods
 *
 * Revision 1.5  2004/01/13 23:37:59  pelle
 * Refactoring parts of the core of XMLSignature. There shouldnt be any real API changes.
 *
 * Revision 1.4  2003/12/11 23:56:53  pelle
 * Trying to test the ReceiverServlet with cactus. Still no luck. Need to return a ElementProxy of some sort.
 * Cleaned up some missing fluff in the ElementProxy interface. getTagName(), getQName() and getNameSpace() have been killed.
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
 * Revision 1.1.1.1  2003/11/11 16:33:25  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.9  2003/11/08 20:27:02  pelle
 * Updated the Signer interface to return a key type to be used for XML SignedInfo. Thus we now support DSA sigs yet again.
 *
 * Revision 1.8  2003/02/24 12:57:37  pelle
 * Sorted out problem with signing enveloping signatures.
 * Canonicalizer needs a Document. If there isn't a Document the xpath wont work and returns false.
 * Thus always have a document for an element.
 *
 * Revision 1.7  2003/02/24 03:26:30  pelle
 * XMLSignature class has been tested as working for Enveloped Signatures.
 * It is still failing verification on home grown Enveloping Signatures.
 * It failes while checking reference validity. This means there is something strange about the Digest is initially
 * calculated for Enveloping signatures.
 *
 * Revision 1.6  2003/02/24 00:41:07  pelle
 * Cleaned up a lot of code for new fixed processing model.
 * It all still work as before, but will be easier to modify the Reference processing model which is the only
 * main thing todo besides X509 and HMAC-SHA1 support.
 *
 * Revision 1.5  2003/02/22 16:54:30  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.4  2003/02/08 19:11:10  pelle
 * Cleaned stuff up a bit.
 *
 * Revision 1.3  2003/02/08 18:48:37  pelle
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
 * Revision 1.2  2003/01/21 03:14:11  pelle
 * Mainly clean ups through out and further documentation.
 *
 * Revision 1.1  2003/01/18 18:12:32  pelle
 * First Independent commit of the Independent XML-Signature API for NeuDist.
 *
 * Revision 1.3  2002/10/10 21:29:31  pelle
 * Oops. XML-Signature's SignedInfo element I had coded as SignedInfo
 * As I thought Canonicalisation doesnt seem to be standard.
 * Updated the SignedServlet to default to using ~/.neuclear/signers.ks
 *
 * Revision 1.2  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 */
package org.neuclear.xml.xmlsec;

/**
 * @author pelleb
 * @version $Revision: 1.5 $
 */

import org.dom4j.Element;
import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.CryptoException;
import org.neuclear.commons.crypto.CryptoTools;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.Signer;
import org.neuclear.xml.XMLException;
import org.neuclear.xml.c14.Canonicalizer;
import org.neuclear.xml.c14.CanonicalizerWithComments;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class SignedInfo extends AbstractXMLSigElement {
    public SignedInfo(Reference references[], final int sigalg) throws XMLSecurityException {
        this(sigalg, references.length);
        for (int i = 0; i < references.length; i++) {
            refs.add(references[i]);
            addElement(references[i]);
        }
    }

    public SignedInfo(final int sigalg, final int refcount) throws XMLSecurityException {
        super(SignedInfo.TAG_NAME);
        refs = new ArrayList(refcount);

        final Element cm = XMLSecTools.createElementInSignatureSpace("CanonicalizationMethod");
        cm.addAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        addElement(cm);

        final Element sm = XMLSecTools.createElementInSignatureSpace("SignatureMethod");
        if (sigalg == SignedInfo.SIG_ALG_RSA)
            sm.addAttribute("Algorithm", DSIG_ALG_RSA);
        else if (sigalg == SignedInfo.SIG_ALG_DSA)
            sm.addAttribute("Algorithm", DSIG_ALG_DSA);
        else
            throw new XMLSecurityException("Unsupported Signature algorithm");

        addElement(sm);
    }

    public SignedInfo(final Element root, final int sigalg, final boolean enveloped) throws XMLSecurityException {
        this(sigalg, 1);

        try {
            Reference ref = new Reference(root, enveloped);
            refs.add(ref);
            addElement(ref);
        } catch (XMLException e) {
            throw new XMLSecurityException(e);
        }
    }

    public SignedInfo(final Element elem) throws XMLSecurityException, InvalidSignatureException {
        super(elem);
        if (!elem.getQName().equals(XMLSecTools.createQName(TAG_NAME)))
            throw new XMLSecurityException("Element: " + elem.getQualifiedName() + " is not a valid: " + XMLSecTools.NS_DS.getPrefix() + ":" + TAG_NAME);
        final List list = elem.elements(XMLSecTools.createQName("Reference"));
        refs = new ArrayList(list.size());
        for (int i = 0; i < list.size(); i++) {
            Element element = (Element) list.get(i);
            refs.add(new Reference(element));
        }
    }

    /**
     * @param elem
     * @throws XMLSecurityException
     */
    public void setEnvelopedReference(final Element elem) throws XMLSecurityException {
        Reference ref = Reference.createEnvelopedReference(elem);
        this.refs.add(ref);
        addElement(ref);
    }

    public void addEnvelopingReference(final Element elem) throws XMLSecurityException {
        Reference ref = Reference.createEnvelopingObjectReference(elem);
        this.refs.add(ref);
        addElement(ref);
    }

    public void addExternalReference(final String url) throws XMLSecurityException {
        Reference ref = Reference.createExternalReference(url);
        this.refs.add(ref);
        addElement(ref);
    }

    /**
     * Method getSigningKey
     * This returns the signing PublicKey if it exists or null if it doesnt.
     * 
     * @return 
     */
    public final List getReferences() {
        return Collections.unmodifiableList(refs);
    }

    /**
     * Returns the Element of the first Reference
     *
     * @return
     */
    public final Element getPrimaryReferenceElement() {
        return ((Reference) refs.get(0)).getReferencedElement();
    }

    /**
     * Returns the first Reference
     *
     * @return
     */
    public final Reference getPrimaryReference() {
        return ((Reference) refs.get(0));
    }

    final Canonicalizer getCanonicalizer() {
        final Element c14elem = getElement().element(XMLSecTools.createQName("CanonicalizationMethod"));
        if (c14elem != null && c14elem.attributeValue("Algorithm").equals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"))
            return new CanonicalizerWithComments();
        return new Canonicalizer();
    }

    // Returns JCE Signature Cipher for SignedInfo
    final Signature getSignatureAlgorithm() throws XMLSecurityException {
        final Element sigElem = getElement().element(XMLSecTools.createQName("SignatureMethod"));
        if (sigElem == null)
            throw new XMLSecurityException("No SignatureMethod element found");

        String algname = sigElem.attributeValue("Algorithm");
        if (Utility.isEmpty(algname))
            throw new XMLSecurityException("No algorithm found in SignatureMethod element");

        try {
            if (algname.equals(DSIG_ALG_RSA))
                return Signature.getInstance(JCE_ALG_RSA);
            if (algname.equals(DSIG_ALG_DSA))
                return Signature.getInstance(JCE_ALG_DSA);
            throw new XMLSecurityException("Unsupported Signature algorithm: " + algname);
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSecurityException(e);
        }
    }

    public final byte[] canonicalize() throws XMLSecurityException {
        return getCanonicalizer().canonicalize(getElement());
    };

    /**
     * Signs the SignedInfo and returns the signature
     *
     * @param key
     * @return
     * @throws XMLSecurityException
     */
    public final byte[] sign(PrivateKey key) throws XMLSecurityException {
        try {
            final byte[] cansi = canonicalize();
            System.out.println("Signing Canonicalized:");
            System.out.println(new String(cansi));
            System.out.println("------");

            return CryptoTools.sign(key, cansi);
        } catch (CryptoException e) {
            throw new XMLSecurityException(e);
        }
    }

    public final byte[] sign(String name, Signer signer) throws XMLSecurityException, NonExistingSignerException, UserCancellationException {
        return signer.sign(name, canonicalize());
    }

    public final boolean verify(PublicKey pub, byte[] sig) throws XMLSecurityException {
        try {
            return CryptoTools.verify(pub, canonicalize(), sig);
        } catch (CryptoException e) {
            throw new XMLSecurityException(e);
        }
    }

    public final String getTagName() {
        return TAG_NAME;
    }

    private static final String TAG_NAME = "SignedInfo";
    private final List refs;

    public final static int SIG_ALG_RSA = Signer.KEY_RSA;
    public final static int SIG_ALG_DSA = Signer.KEY_DSA;

    public final static String DSIG_ALG_RSA = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    public final static String DSIG_ALG_DSA = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
    public final static String JCE_ALG_RSA = "SHA1withRSA";
    public final static String JCE_ALG_DSA = "SHA1withDSA";

    //   private PublicKey pub;
}
