/* $Id: XMLSignature.java,v 1.13 2004/03/02 18:39:57 pelle Exp $
 * $Log: XMLSignature.java,v $
 * Revision 1.13  2004/03/02 18:39:57  pelle
 * Done some more minor fixes within xmlsig, but mainly I've removed the old Source and Store patterns and sub packages. This is because
 * they really are no longer necessary with the new non naming naming system.
 *
 * Revision 1.12  2004/02/19 00:27:59  pelle
 * Discovered several incompatabilities with the xmlsig implementation. Have been working on getting it working.
 * Currently there is still a problem with enveloping signatures and it seems enveloped signatures done via signers.
 *
 * Revision 1.11  2004/01/15 00:01:46  pelle
 * Problem fixed with Enveloping signatures.
 *
 * Revision 1.10  2004/01/14 06:42:38  pelle
 * Got rid of the verifyXXX() methods
 *
 * Revision 1.9  2004/01/13 23:37:59  pelle
 * Refactoring parts of the core of XMLSignature. There shouldnt be any real API changes.
 *
 * Revision 1.8  2004/01/08 23:38:06  pelle
 * XMLSignature can now give you the Signing key and the id of the signer.
 * SignedElement can now self verify using embedded public keys as well as KeyName's
 * Added NeuclearKeyResolver for resolving public key's from Identity certificates.
 * SignedNamedObjects can now generate their own name using the following format:
 * neu:sha1://[sha1 of PublicKey]![sha1 of full signed object]
 * The resulting object has a special internally generted Identity containing the PublicKey
 * Identity can now contain nothing but a public key
 *
 * Revision 1.7  2004/01/07 23:11:51  pelle
 * XMLSig now has various added features:
 * -  KeyInfo supports X509v3 (untested)
 * -  KeyInfo supports KeyName
 * -  When creating a XMLSignature and signing it with a Signer, it adds the alias to the KeyName
 * Added KeyResolver interface and KeyResolverFactory Class. At the moment no implementations.
 *
 * Revision 1.6  2003/12/19 18:03:07  pelle
 * Revamped a lot of exception handling throughout the framework, it has been simplified in most places:
 * - For most cases the main exception to worry about now is InvalidNamedObjectException.
 * - Most lowerlevel exception that cant be handled meaningful are now wrapped in the LowLevelException, a
 *   runtime exception.
 * - Source and Store patterns each now have their own exceptions that generalizes the various physical
 *   exceptions that can happen in that area.
 *
 * Revision 1.5  2003/12/11 23:56:53  pelle
 * Trying to test the ReceiverServlet with cactus. Still no luck. Need to return a ElementProxy of some sort.
 * Cleaned up some missing fluff in the ElementProxy interface. getTagName(), getQName() and getNameSpace() have been killed.
 *
 * Revision 1.4  2003/12/10 23:57:05  pelle
 * Did some cleaning up in the builders
 * Fixed some stuff in IdentityCreator
 * New maven goal to create executable jarapp
 * We are close to 0.8 final of ID, 0.11 final of XMLSIG and 0.5 of commons.
 * Will release shortly.
 *
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
 * This means that it is now possible to further receive on or process a SignedNamedObject, leaving
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
 * @version $Revision: 1.13 $
 */

import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.neuclear.commons.crypto.CryptoException;
import org.neuclear.commons.crypto.CryptoTools;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.PublicKeySource;
import org.neuclear.commons.crypto.signers.Signer;
import org.neuclear.xml.XMLException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Encapsulates a XML Digital Signature.    <p>
 * This is the base class of Digital Signatures
 */
public class XMLSignature extends AbstractXMLSigElement {
    /**
     * Creates an Enveloped (Embedded) Signature object based on the given element root
     * 
     * @param keypair 
     * @param root    
     * @throws XMLSecurityException
     */
    public XMLSignature(final KeyPair keypair, final Element root) throws XMLSecurityException, CryptoException {
        this(keypair.getPrivate(), keypair.getPublic(), root);
    }

    /**
     * Creates a Signature object based on given element root.
     * 
     * @param keypair 
     * @param root    
     * @param type    Reference.XMLSIGTYPE_ENVELOPED,Reference.XMLSIGTYPE_ENVELOPING or Reference.XMLSIGTYPE_DETACHED
     * @throws XMLSecurityException 
     */
    public XMLSignature(final KeyPair keypair, final Element root, final int type) throws XMLSecurityException, CryptoException {
        this(keypair.getPrivate(), keypair.getPublic(), root, type);
    }

    public XMLSignature(final PrivateKey key, final PublicKey pub, final Element root) throws XMLSecurityException, CryptoException {
        this(key, pub, root, Reference.XMLSIGTYPE_ENVELOPED);

    }

    //TODO Something does not work right with Enveloping signatures. I am trying to figure out what it is. However enveloped are all
    // that we need for NeuClear, so I may put this on the backburner.
    public XMLSignature(final PrivateKey key, final PublicKey pub, Element root, final int type) throws XMLSecurityException, CryptoException {
        super(XMLSignature.TAG_NAME);
        try {
             if (type == Reference.XMLSIGTYPE_ENVELOPED) {
                root.add(getElement());
             } else if (type == Reference.XMLSIGTYPE_ENVELOPING) {
                final Element objElem = XMLSecTools.createElementInSignatureSpace("Object");
                objElem.addAttribute("Id","data");
                DocumentHelper.createDocument(getElement());//As Signature Element is parent we will now add a doc
                objElem.add(root);
                root = objElem;
                getElement().add(root);
            }
            final int alg = (key instanceof RSAPrivateKey) ? SignatureInfo.SIG_ALG_RSA : SignatureInfo.SIG_ALG_DSA;
            si = new SignatureInfo( root,  alg, type);
            addElement(si);
            final byte[] cansi = si.canonicalize();
//            System.out.println("Canonicalized:");
//            System.out.println(new String(cansi));
//            System.out.println("------");
            addElement(XMLSecTools.base64ToElement("SignatureValue", CryptoTools.sign(key, cansi)));
            if (pub != null)
                addElement(new KeyInfo(pub));
            // If Enveloping add Object element last
            if (type == Reference.XMLSIGTYPE_ENVELOPING) {
                getElement().remove(root);
                getElement().add(root);
            }
        } catch (XMLException e) {
            throw new XMLSecurityException(e);
        }
    }
    public XMLSignature(final String name, final Signer signer, Element root,final int type) throws XMLSecurityException, NonExistingSignerException, UserCancellationException {
        super(XMLSignature.TAG_NAME);
        if (! (signer instanceof PublicKeySource))
            throw new XMLSecurityException("We Require a PublicKeySource");
        PublicKeySource src=(PublicKeySource)signer;
        try {
            if (type == Reference.XMLSIGTYPE_ENVELOPED) {
               root.add(getElement());
            } else if (type == Reference.XMLSIGTYPE_ENVELOPING) {
               final Element objElem = XMLSecTools.createElementInSignatureSpace("Object");
               objElem.addAttribute("Id","data");
               DocumentHelper.createDocument(getElement());//As Signature Element is parent we will now add a doc
               objElem.add(root);
               root = objElem;
               getElement().add(root);
           }
            final PublicKey pub = src.getPublicKey(name);
            final int alg = (pub instanceof RSAPublicKey) ? SignatureInfo.SIG_ALG_RSA : SignatureInfo.SIG_ALG_DSA;
            si = new SignatureInfo( root,  alg, type);
            addElement(si);
            final byte[] cansi = si.canonicalize();
//            System.out.println("Canonicalized:");
//            System.out.println(new String(cansi));
//            System.out.println("------");
            addElement(XMLSecTools.base64ToElement("SignatureValue", signer.sign(name, cansi)));
            final KeyInfo key = new KeyInfo(pub);
            addElement(key);
            if (type == Reference.XMLSIGTYPE_ENVELOPING) {
                getElement().remove(root);
                getElement().add(root);
            }
        } catch (XMLException e) {
            throw new XMLSecurityException(e);
        }
    }

    public XMLSignature(final Element elem) throws XMLSecurityException, InvalidSignatureException {
        super(elem);
        final Element siElem = elem.element(XMLSecTools.createQName("SignedInfo"));
        if (!elem.getQName().equals(XMLSecTools.createQName(TAG_NAME)) || siElem == null)  // Not sure if equals is imeplemented properly for QNames
            throw new XMLSecurityException("Element: " + elem.getQualifiedName() + " is not a valid: " + XMLSecTools.NS_DS.getPrefix() + ":" + TAG_NAME);
        si = new SignatureInfo(siElem);
        KeyInfo key=getKeyInfo();
        if (key == null)
            throw new XMLSecurityException("No included PublicKey, can not verify.");

        final byte[] sig = getSignature();
        final byte[] cansi = si.canonicalize();
//        System.out.println("Canonicalized:");
//        System.out.println(new String(cansi));
//        System.out.println("------");

        try {
            if (!CryptoTools.verify(key.getPublicKey(), cansi, sig))
                throw new InvalidSignatureException(key.getPublicKey());
        } catch (CryptoException e) {
            throw new XMLSecurityException(e);
        }
    }

    public XMLSignature(final Element elem,PublicKey pub) throws XMLSecurityException, InvalidSignatureException {
        super(elem);
        final Element siElem = elem.element(XMLSecTools.createQName("SignedInfo"));
        if (!elem.getQName().equals(XMLSecTools.createQName(TAG_NAME)) || siElem == null)  // Not sure if equals is imeplemented properly for QNames
            throw new XMLSecurityException("Element: " + elem.getQualifiedName() + " is not a valid: " + XMLSecTools.NS_DS.getPrefix() + ":" + TAG_NAME);
        si = new SignatureInfo(siElem);
        final byte[] sig = getSignature();
        final byte[] cansi = si.canonicalize();
        try {
            if (!CryptoTools.verify(pub, cansi, sig))
                throw new InvalidSignatureException(pub);
        } catch (CryptoException e) {
            throw new XMLSecurityException(e);
        }
    }

    /**
     * Method getPublicKey
     * 
     * @return 
     * @throws XMLSecurityException 
     */
    private final byte[] getSignature() throws XMLSecurityException {
        final Element sigVal = getElement().element("SignatureValue");
        return XMLSecTools.decodeBase64Element(sigVal);
    }

    public final PublicKey getSignersKey() throws XMLSecurityException {
        KeyInfo key=getKeyInfo();
        if (key == null)
            return null;
        return key.getPublicKey();
    }
    public final String getSignersId() throws XMLSecurityException {
        KeyInfo key=getKeyInfo();
        if (key == null)
            return null;
        return key.getKeyName();
    }
    private final synchronized KeyInfo getKeyInfo() throws XMLSecurityException{
        if (ki==null){
            final Element keyInfoElem = getElement().element(XMLSecTools.createQName("KeyInfo"));
            if (keyInfoElem != null)
                ki=new KeyInfo(keyInfoElem);
        }
        return ki;
    }

    protected final SignatureInfo getSi() {
        return si;
    }

    private SignatureInfo si;
    private KeyInfo ki;
    private static final String TAG_NAME = "Signature";
    //   private PublicKey pub;
}
