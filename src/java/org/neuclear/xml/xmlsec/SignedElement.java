/* $Id: SignedElement.java,v 1.12 2004/03/19 22:21:51 pelle Exp $
 * $Log: SignedElement.java,v $
 * Revision 1.12  2004/03/19 22:21:51  pelle
 * Changes in the XMLSignature class, which is now Abstract there are currently 3 implementations for:
 * - Enveloped
 * - DataObjects - (Enveloping)
 * - Any for interop testing mainly.
 *
 * Revision 1.11  2004/03/08 23:51:03  pelle
 * More improvements on the XMLSignature. Now uses the Transforms properly, References properly.
 * All the major elements have been refactored to be cleaner and more correct.
 *
 * Revision 1.10  2004/01/14 06:42:38  pelle
 * Got rid of the verifyXXX() methods
 *
 * Revision 1.9  2004/01/13 23:37:59  pelle
 * Refactoring parts of the core of XMLSignature. There shouldnt be any real API changes.
 *
 * Revision 1.8  2004/01/11 00:39:19  pelle
 * Cleaned up the schemas even more they now all verifiy.
 * The Order/Receipt pairs for neuclear pay, should now work. They all have Readers using the latest
 * Schema.
 * The TransferBuilders are done and the ExchangeBuilders are nearly there.
 * The new EmbeddedSignedNamedObject builder is useful for creating new Receipts. The new ReceiptBuilder uses
 * this to create the embedded transaction.
 * ExchangeOrders now have the concept of BidItem's, you could create an ExchangeOrder bidding on various items at the same time, to be exchanged as one atomic multiparty exchange.
 * Still doesnt build yet, but very close now ;-)
 *
 * Revision 1.7  2004/01/08 23:38:06  pelle
 * XMLSignature can now give you the Signing key and the id of the signer.
 * SignedElement can now self verify using embedded public keys as well as KeyName's
 * Added NeuclearKeyResolver for resolving public key's from Identity certificates.
 * SignedNamedObjects can now generate their own name using the following format:
 * neu:sha1://[sha1 of PublicKey]![sha1 of full signed object]
 * The resulting object has a special internally generted Identity containing the PublicKey
 * Identity can now contain nothing but a public key
 *
 * Revision 1.6  2003/12/19 18:03:07  pelle
 * Revamped a lot of exception handling throughout the framework, it has been simplified in most places:
 * - For most cases the main exception to worry about now is InvalidNamedObjectException.
 * - Most lowerlevel exception that cant be handled meaningful are now wrapped in the LowLevelException, a
 *   runtime exception.
 * - Source and Store patterns each now have their own exceptions that generalizes the various physical
 *   exceptions that can happen in that area.
 *
 * Revision 1.5  2003/12/10 23:57:05  pelle
 * Did some cleaning up in the builders
 * Fixed some stuff in IdentityCreator
 * New maven goal to create executable jarapp
 * We are close to 0.8 final of ID, 0.11 final of XMLSIG and 0.5 of commons.
 * Will release shortly.
 *
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
 * This means that it is now possible to further receive on or process a SignedNamedObject, leaving
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
 * @version $Revision: 1.12 $
 */

import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.Signer;
import org.neuclear.xml.AbstractElementProxy;
import org.neuclear.xml.XMLException;


public abstract class SignedElement extends AbstractElementProxy {
    private EnvelopedSignature sig;

    public SignedElement(final QName qname) {
        super(qname);
    }

    public SignedElement(final Element elem) throws XMLSecurityException {
        super(elem);
        final Element sigElement = getElement().element(XMLSecTools.createQName("Signature"));
        if (sigElement != null)
            try {
                sig = new EnvelopedSignature(sigElement);
            } catch (XMLException e) {
                throw new XMLSecurityException(e);
            } catch (InvalidSignatureException e) {
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

    public boolean verify() throws XMLSecurityException {
        try {
            if (sig == null) ;
            sig = new EnvelopedSignature(getElement());

            return true;

        } catch (InvalidSignatureException e) {
            return false;
        }
    }

    public final void sign(final String name, final Signer signer) throws XMLSecurityException, UserCancellationException, NonExistingSignerException {
        preSign();
        sig = new EnvelopedSignature(name, signer, getElement());
        postSign();
    }

}
