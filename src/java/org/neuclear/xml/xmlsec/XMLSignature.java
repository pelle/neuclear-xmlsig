/* $Id: XMLSignature.java,v 1.3 2003/11/21 04:44:31 pelle Exp $
 * $Log: XMLSignature.java,v $
 * Revision 1.3  2003/11/21 04:44:31  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.2  2003/11/19 23:33:17  pelle
 * Signers now can generatekeys via the generateKey() method.
 * Refactored the relationship between SignedNamedObject and NamedObjectBuilder a bit.
 * SignedNamedObject now contains the full xml which is returned with getEncoded()
 * This means that it is now possible to further send on or process a SignedNamedObject, leaving
 * NamedObjectBuilder for its original purposes of purely generating new Contracts.
 * NamedObjectBuilder.sign() now returns a SignedNamedObject which is the prefered way of processing it.
 * Updated all major interfaces that used the old model to use the new model.
 *
 * Revision 1.1.1.1  2003/11/11 16:33:27  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.18  2003/11/09 03:27:09  pelle
 * More house keeping and shuffling about mainly pay
 *
 * Revision 1.17  2003/10/02 23:29:34  pelle
 * Updated Root Key. This will be the root key for the remainder of the beta period. With version 1.0 I will update it with a new key.
 * VerifyingTest works now and also does a pass for fake ones. Will have to think of better ways of making fake Identities to break it.
 * Cleaned up much of the tests and they all pass now.
 * The FileStoreTests need to be rethought out, by adding a test key.
 *
 * Revision 1.16  2003/09/26 23:52:47  pelle
 * Changes mainly in receiver and related fun.
 * First real neuclear stuff in the payment package. Added TransferContract and AssetControllerReceiver.
 *
 * Revision 1.15  2003/02/24 13:32:24  pelle
 * Final doc changes for 0.8
 *
 * Revision 1.14  2003/02/24 12:57:37  pelle
 * Sorted out problem with signing enveloping signatures.
 * Canonicalizer needs a Document. If there isn't a Document the xpath wont work and returns false.
 * Thus always have a document for an element.
 *
 * Revision 1.13  2003/02/24 03:26:30  pelle
 * XMLSignature class has been tested as working for Enveloped Signatures.
 * It is still failing verification on home grown Enveloping Signatures.
 * It failes while checking reference validity. This means there is something strange about the Digest is initially
 * calculated for Enveloping signatures.
 *
 * Revision 1.12  2003/02/24 00:41:07  pelle
 * Cleaned up a lot of code for new fixed processing model.
 * It all still work as before, but will be easier to modify the Reference processing model which is the only
 * main thing todo besides X509 and HMAC-SHA1 support.
 *
 * Revision 1.11  2003/02/23 23:21:47  pelle
 * Yeah. We figured it out. We now have interop.
 * Granted not on all features as yet, but definitely on simple signatures.
 * I'm checking in Ramses' fix to QuickEmbeddedSignature and my fixes to the verification process.
 *
 * Revision 1.10  2003/02/22 23:19:10  pelle
 * Additional fixes to the encoding problem.
 *
 * Revision 1.9  2003/02/22 16:54:30  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.8  2003/02/21 22:48:17  pelle
 * New Test Infrastructure
 * Added test keys in src/testdata/keys
 * Modified tools to handle these keys
 *
 * Revision 1.7  2003/02/14 21:14:08  pelle
 * The AbstractElementProxy has a new final method .asXML()
 * which is similar to DOM4J's but it outputs the xml in the compact format and not the pretty format, thus not causing problems with Canonicalization.
 * You can now also easily get the digest of a SignedElement with the new .getEncoded() value.
 *
 * Revision 1.6  2003/02/11 14:50:24  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
 *
 * Revision 1.5  2003/02/08 20:55:08  pelle
 * Some documentation changes.
 * Major reorganization of code. The code is slowly being cleaned up in such a way that we can
 * get rid of the org.neuclear.utils package and split out the org.neuclear.xml.soap package.
 * Got rid of tons of unnecessary dependencies.
 *
 * Revision 1.4  2003/02/08 19:11:10  pelle
 * Cleaned stuff up a bit.
 *
 * Revision 1.3  2003/02/08 18:48:38  pelle
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
 * Revision 1.5  2003/01/16 19:16:09  pelle
 * Major Structural Changes.
 * We've split the test classes out of the normal source tree, to enable Maven's test support to work.
 * WARNING
 * for Development purposes the code does not as of this commit until otherwise notified actually verifysigs.
 * We are reworking the XMLSig library and need to continue work elsewhere for the time being.
 * DO NOT USE THIS FOR REAL APPS
 *
 * Revision 1.4  2002/10/10 21:29:31  pelle
 * Oops. XML-Signature's SignedInfo element I had coded as SignatureInfo
 * As I thought Canonicalisation doesnt seem to be standard.
 * Updated the SignedServlet to default to using ~/.neuclear/signers.ks
 *
 * Revision 1.3  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 */
package org.neuclear.xml.xmlsec;

/**
 * @author pelleb
 * @version $Revision: 1.3 $
 */

import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.neuclear.commons.crypto.CryptoException;
import org.neuclear.commons.crypto.CryptoTools;
import org.neuclear.xml.XMLException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;

/**
 * Encapsulates a XML Digital Signature.    <p>
 * This is the base class of Digital Signatures
 */
public class XMLSignature extends AbstractXMLSigElement {
    /**
     * Creates an Enveloped (Embedded) Signature object based on the given element root
     * 
     * @param key  
     * @param root 
     * @param uri  
     * @throws XMLSecurityException 
     */
    public XMLSignature(final PrivateKey key, final Element root, final String uri) throws XMLSecurityException, CryptoException {
        this(key, null, root, uri);
    }

    /**
     * Creates an Enveloped (Embedded) Signature object based on the given element root
     * 
     * @param keypair 
     * @param root    
     * @param uri     
     * @throws XMLSecurityException 
     */
    public XMLSignature(final KeyPair keypair, final Element root, final String uri) throws XMLSecurityException, CryptoException {
        this(keypair.getPrivate(), keypair.getPublic(), root, uri);
    }

    /**
     * Creates a Signature object based on given element root.
     * 
     * @param keypair 
     * @param root    
     * @param uri     
     * @param type    Reference.XMLSIGTYPE_ENVELOPED,Reference.XMLSIGTYPE_ENVELOPING or Reference.XMLSIGTYPE_DETACHED
     * @throws XMLSecurityException 
     */
    public XMLSignature(final KeyPair keypair, final Element root, final String uri, final int type) throws XMLSecurityException, CryptoException {
        this(keypair.getPrivate(), keypair.getPublic(), root, uri, type);
    }

    public XMLSignature(final PrivateKey key, final PublicKey pub, final Element root, final String uri) throws XMLSecurityException, CryptoException {
        this(key, pub, root, uri, Reference.XMLSIGTYPE_ENVELOPED);

    }

    public XMLSignature(final PrivateKey key, final PublicKey pub, Element root, final String uri, final int type) throws XMLSecurityException, CryptoException {
        super(XMLSignature.TAG_NAME);
        try {
            if (type == Reference.XMLSIGTYPE_ENVELOPED) {
                root.add(getElement());
            } else if (type == Reference.XMLSIGTYPE_ENVELOPING) {
                final Element objElem = XMLSecTools.createElementInSignatureSpace("Object");
                getElement().add(objElem);
                DocumentHelper.createDocument(getElement());//As Signature Element is parent we will now add a doc
                objElem.add(root);
                root = objElem;
            } else {
                // Detached Handle this in the Ference Constructor
            }
            final int alg = (key instanceof RSAPrivateKey) ? SignatureInfo.SIG_ALG_RSA : SignatureInfo.SIG_ALG_DSA;
            si = new SignatureInfo(this, root, uri, alg, type);
            addElement(si);
            addElement(XMLSecTools.base64ToElement("SignatureValue", CryptoTools.sign(key, si.canonicalize())));
            if (pub != null)
                addElement(new KeyInfo(pub));
        } catch (XMLException e) {
            throw new XMLSecurityException(e);
        }
    }

    public XMLSignature(final Element elem) throws XMLSecurityException {
        super(elem);
        final Element siElem = elem.element(XMLSecTools.createQName("SignedInfo"));
        if (!elem.getQName().equals(getQName()) || siElem == null)  // Not sure if equals is imeplemented properly for QNames
            throw new XMLSecurityException("Element: " + elem.getQualifiedName() + " is not a valid: " + XMLSecTools.NS_DS.getPrefix() + ":" + TAG_NAME);
        si = new SignatureInfo(this, siElem);

    }

    /**
     * Method getPublicKey
     * 
     * @return 
     * @throws XMLSecurityException 
     */
    public final byte[] getSignature() throws XMLSecurityException, CryptoException {
        final Element sigVal = getElement().element("SignatureValue");
        return XMLSecTools.decodeBase64Element(sigVal);
    }

    public final boolean verifySignature() throws XMLSecurityException, CryptoException {
        final Element keyInfoElem = getElement().element(XMLSecTools.createQName("KeyInfo"));
        if (keyInfoElem == null)
            throw new XMLSecurityException("Signature does not contain an embedded PublicKey");
        final KeyInfo ki = new KeyInfo(keyInfoElem);
        final PublicKey pk = ki.getPublicKey();
        return verifySignature(pk);
    }

    public final boolean verifySignature(final PublicKey pk) throws XMLSecurityException, CryptoException {

        if (!si.getReference().verifyReferences())
            return false;
        final byte[] sig = getSignature();
        final byte[] cansi = si.canonicalize();
        return CryptoTools.verify(pk, cansi, sig);
    }

    public final boolean verifySignature(final PublicKey[] pks) throws XMLSecurityException, CryptoException {

        if (!si.getReference().verifyReferences()) {
//            System.err.println("XMLSIG: References didnt match up");
            return false;
        }
        final byte[] sig = getSignature();
        final byte[] cansi = si.canonicalize();
        for (int i = 0; i < pks.length; i++)
            if (CryptoTools.verify(pks[i], cansi, sig))
                return true;
//        System.err.println("XMLSIG: Signature didnt Verify");
        return false;
    }


    public final String getTagName() {
        return TAG_NAME;
    }

    public final byte[] getDigest() throws XMLSecurityException, CryptoException {
        if (si == null)
            throw new XMLSecurityException("The object can not be verified as it doesnt contain a signature");
        return si.getReference().getDigest();
    }

    protected final SignatureInfo getSi() {
        return si;
    }

    private SignatureInfo si;
    private static final String TAG_NAME = "Signature";
    //   private PublicKey pub;
}
