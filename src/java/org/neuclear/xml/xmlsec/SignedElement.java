/* $Id: SignedElement.java,v 1.4 2003/11/21 04:44:31 pelle Exp $
 * $Log: SignedElement.java,v $
 * Revision 1.4  2003/11/21 04:44:31  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.3  2003/11/19 23:33:17  pelle
 * Signers now can generatekeys via the generateKey() method.
 * Refactored the relationship between SignedNamedObject and NamedObjectBuilder a bit.
 * SignedNamedObject now contains the full xml which is returned with getEncoded()
 * This means that it is now possible to further send on or process a SignedNamedObject, leaving
 * NamedObjectBuilder for its original purposes of purely generating new Contracts.
 * NamedObjectBuilder.sign() now returns a SignedNamedObject which is the prefered way of processing it.
 * Updated all major interfaces that used the old model to use the new model.
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
 * Revision 1.6  2003/11/09 03:27:09  pelle
 * More house keeping and shuffling about mainly pay
 *
 * Revision 1.5  2003/10/29 21:15:53  pelle
 * Refactored the whole signing process. Now we have an interface called Signer which is the old SignerStore.
 * To use it you pass a byte array and an alias. The sign method then returns the signature.
 * If a Signer needs a passphrase it uses a PassPhraseAgent to present a dialogue box, read it from a command line etc.
 * This new Signer pattern allows us to use secure signing hardware such as N-Cipher in the future for server applications as well
 * as SmartCards for end user applications.
 *
 * Revision 1.4  2003/09/26 23:52:47  pelle
 * Changes mainly in receiver and related fun.
 * First real neuclear stuff in the payment package. Added TransferContract and AssetControllerReceiver.
 *
 * Revision 1.3  2003/02/14 21:14:08  pelle
 * The AbstractElementProxy has a new final method .asXML()
 * which is similar to DOM4J's but it outputs the xml in the compact format and not the pretty format, thus not causing problems with Canonicalization.
 * You can now also easily get the digest of a SignedElement with the new .getEncoded() value.
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
 * Revision 1.1  2003/01/21 03:14:11  pelle
 * Mainly clean ups through out and further documentation.
 *
 * Revision 1.1  2003/01/18 18:12:32  pelle
 * First Independent commit of the Independent XML-Signature API for NeuDist.
 *
 * Revision 1.2  2003/01/16 19:16:09  pelle
 * Major Structural Changes.
 * We've split the test classes out of the normal source tree, to enable Maven's test support to work.
 * WARNING
 * for Development purposes the code does not as of this commit until otherwise notified actually verifysigs.
 * We are reworking the XMLSig library and need to continue work elsewhere for the time being.
 * DO NOT USE THIS FOR REAL APPS
 *
 * Revision 1.1  2002/12/17 21:53:29  pelle
 * Final changes for refactoring.
 *
 * Revision 1.4  2002/12/17 21:41:04  pelle
 * First part of refactoring of SignedNamedObject and SignedObject Interface/Class parings.
 *
 * Revision 1.3  2002/12/17 20:34:44  pelle
 * Lots of changes to core functionality.
 * First of all I've refactored most of the Resolving and verification code. I have a few more things to do
 * on it before I'm happy.
 * There is now a NSResolver class, which handles all the namespace resolution. I took most of the functionality
 * for this out of SignedNamedObject.
 * Then there is the veriifer, which verifies a given SignedNamedObject using the NSResolver.
 * This has simplified the SignedNamedObject classes drastically, leaving them as mainly data objects, which is what they
 * should be.
 * I have also gone around and tightened up security on many different classes, making clases and/or methods final where appropriate.
 * NSCache now operates using http://www.waterken.com's fantastic ADT collections library.
 * Something important has been added, which is a SignRequest named object. This signed object, embeds an unsigned
 * named object for signing by an end users' signing service.
 * Now were almost ready to start seriously implementing AssetIssuers and Transfers, which will be the most important
 * part of the framework.
 *
 * Revision 1.2  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 */
package org.neuclear.xml.xmlsec;

/**
 * @author pelleb
 * @version $Revision: 1.4 $
 */

import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;
import org.neuclear.commons.crypto.CryptoException;
import org.neuclear.commons.crypto.signers.Signer;
import org.neuclear.xml.AbstractElementProxy;
import org.neuclear.xml.XMLException;

import java.security.PrivateKey;
import java.security.PublicKey;


public abstract class SignedElement extends AbstractElementProxy {
    private XMLSignature sig;

    public SignedElement(final QName qname) {
        super(qname);
    }

    public SignedElement(final Element elem) throws XMLSecurityException {
        super(elem);
        final Element sigElement = getElement().element(XMLSecTools.createQName("Signature"));
        if (sigElement != null)
            try {
                sig = new XMLSignature(sigElement);
            } catch (XMLException e) {
                throw new XMLSecurityException(e);
            }

    }

    public SignedElement(final String name, final Namespace ns) {
        super(name, ns);
    }

    public SignedElement(final String name, final String prefix, final String nsURI) {
        super(name, prefix, nsURI);
    }

    /**
     * This is called before signing to handle any pre signing tasks such as time stamps.
     * 
     * @throws XMLSecurityException 
     */
    protected void preSign() throws XMLSecurityException {
        ;
    }

    /**
     * This is called after signing to handle any post signing tasks such as logging
     * 
     * @throws XMLSecurityException 
     */
    protected final void postSign() throws XMLSecurityException {
        ;
    }

    /**
     * Checks if a SignedNamedObject contains a signature.<br>
     * IMPORTANT: True only indicates that it contains a signature, not that it is valid.
     */
    public final boolean isSigned() {
        return (sig != null);
    }

    /**
     * The signature for this object. This must match the allowed signers for the parent namespace
     * 
     * @return An XMLSignature objects
     */
    public final XMLSignature getXMLSignature() throws XMLSecurityException {
        return sig;
    }

    /**
     * This verifies the signature of the object.
     */
    public final boolean verifySignature(final PublicKey pub) throws XMLSecurityException, CryptoException {
        if (sig == null)
            throw new XMLSecurityException("The object can not be verified as it doesnt contain a signature");
        return sig.verifySignature(pub);
    }

    /**
     * Sign object using given PrivateKey. This also adds a timestamp to the root element prior to signing
     */
    public final void sign(final PrivateKey priv) throws XMLSecurityException, CryptoException {
        preSign();
        sig = XMLSecTools.signElement(getURI(), getElement(), priv);
        postSign();
    }

    public final void sign(final String name, final Signer signer) throws XMLSecurityException, CryptoException {
        preSign();
        sig = XMLSecTools.signElement(getURI(), getElement(), name, signer);
        postSign();
    }

    /**
     * @return 
     * @throws XMLSecurityException 
     */

    public final byte[] getDigest() throws XMLSecurityException, CryptoException {
        if (sig == null)
            throw new XMLSecurityException("The object can not be verified as it doesnt contain a signature");
        return sig.getDigest();
    }

    /**
     * Returns the URI of the Element. This is used in the signing process.
     */
    public abstract String getURI() throws XMLSecurityException;

}
