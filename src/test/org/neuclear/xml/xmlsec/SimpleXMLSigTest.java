package org.neuclear.xml.xmlsec;

import junit.framework.TestCase;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.io.XPP3Reader;
import org.dom4j.io.XPPReader;
import org.neuclear.commons.crypto.CryptoException;
import org.neuclear.commons.crypto.CryptoTools;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.Signer;
import org.neuclear.commons.crypto.signers.TestCaseSigner;
import org.neuclear.xml.XMLException;
import org.neuclear.xml.XMLTools;

import java.io.File;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;

/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 20, 2003
 * Time: 3:49:27 PM
 * $Id: SimpleXMLSigTest.java,v 1.16 2004/09/07 19:28:19 pelle Exp $
 * $Log: SimpleXMLSigTest.java,v $
 * Revision 1.16  2004/09/07 19:28:19  pelle
 * Removed some non working features.
 *
 * Revision 1.15  2004/09/07 18:48:03  pelle
 * Added support for dom4j 1.5 and added a new XPP3Reader
 * <p/>
 * Revision 1.14  2004/04/16 23:54:03  pelle
 * Added HTMLSignature with tests and associated changes in StandaloneSigner
 * <p/>
 * Revision 1.13  2004/03/23 20:51:00  pelle
 * Added ExternalSignature and further Javadocs.
 * Added Busy Developers Guide and Interop guide.
 * Ready for release.
 * <p/>
 * Revision 1.12  2004/03/19 22:21:51  pelle
 * Changes in the XMLSignature class, which is now Abstract there are currently 3 implementations for:
 * - Enveloped
 * - DataObjects - (Enveloping)
 * - Any for interop testing mainly.
 * <p/>
 * Revision 1.11  2004/03/08 23:51:04  pelle
 * More improvements on the XMLSignature. Now uses the Transforms properly, References properly.
 * All the major elements have been refactored to be cleaner and more correct.
 * <p/>
 * Revision 1.10  2004/03/02 23:30:44  pelle
 * Renamed SignatureInfo to SignedInfo as that is the name of the Element.
 * Made some changes in the Canonicalizer to make all the output verify in Aleksey's xmlsec library.
 * Unfortunately this breaks example 3 of merlin-eight's canonicalization interop tests, because dom4j afaik
 * can't tell the difference between <test/> and <test xmlns=""/>.
 * Changed XMLSignature it is now has less repeated code.
 * <p/>
 * Revision 1.9  2004/03/02 18:39:57  pelle
 * Done some more minor fixes within xmlsig, but mainly I've removed the old Source and Store patterns and sub packages. This is because
 * they really are no longer necessary with the new non naming naming system.
 * <p/>
 * Revision 1.8  2004/02/19 00:28:00  pelle
 * Discovered several incompatabilities with the xmlsig implementation. Have been working on getting it working.
 * Currently there is still a problem with enveloping signatures and it seems enveloped signatures done via signers.
 * <p/>
 * Revision 1.7  2004/01/14 06:42:38  pelle
 * Got rid of the verifyXXX() methods
 * <p/>
 * Revision 1.6  2004/01/13 23:37:59  pelle
 * Refactoring parts of the core of XMLSignature. There shouldnt be any real API changes.
 * <p/>
 * Revision 1.5  2003/11/21 04:44:31  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 * <p/>
 * Revision 1.4  2003/11/20 23:41:58  pelle
 * Getting all the tests to work in id
 * Removing usage of BC in CryptoTools as it was causing issues.
 * First version of EntityLedger that will use OFB's EntityEngine. This will allow us to support a vast amount databases without
 * writing SQL. (Yipee)
 * <p/>
 * Revision 1.3  2003/11/18 23:35:18  pelle
 * Payment Web Application is getting there.
 * <p/>
 * Revision 1.2  2003/11/11 21:18:08  pelle
 * Further vital reshuffling.
 * org.neudist.crypto.* and org.neudist.utils.* have been moved to respective areas under org.neuclear.commons
 * org.neuclear.signers.* as well as org.neuclear.passphraseagents have been moved under org.neuclear.commons.crypto as well.
 * Did a bit of work on the Canonicalizer and changed a few other minor bits.
 * <p/>
 * Revision 1.1.1.1  2003/11/11 16:33:32  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 * <p/>
 * Revision 1.9  2003/10/21 22:30:34  pelle
 * Renamed NeudistException to NeuClearException and moved it to org.neuclear.commons where it makes more sense.
 * Unhooked the XMLException in the xmlsig library from NeuClearException to make all of its exceptions an independent hierarchy.
 * Obviously had to perform many changes throughout the code to support these changes.
 * <p/>
 * Revision 1.8  2003/02/24 12:57:56  pelle
 * Sorted out problem with signing enveloping signatures.
 * Canonicalizer needs a Document. If there isn't a Document the xpath wont work and returns false.
 * Thus always have a document for an element.
 * <p/>
 * Revision 1.7  2003/02/24 03:26:30  pelle
 * XMLSignature class has been tested as working for Enveloped Signatures.
 * It is still failing verification on home grown Enveloping Signatures.
 * It failes while checking reference validity. This means there is something strange about the Digest is initially
 * calculated for Enveloping signatures.
 * <p/>
 * Revision 1.6  2003/02/21 22:48:20  pelle
 * New Test Infrastructure
 * Added test keys in src/testdata/keys
 * Modified tools to handle these keys
 * <p/>
 * Revision 1.5  2003/02/20 13:26:42  pelle
 * Adding all of the modification from Rams?s Morales ramses@computer.org to support DSASHA1 Signatures
 * Thanks Rams?s good work.
 * So this means there is now support for:
 * - DSA KeyInfo blocks
 * - DSA Key Generation within CryptoTools
 * - Signing using DSASHA1
 * <p/>
 * Revision 1.4  2003/02/11 14:50:26  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
 * <p/>
 * Revision 1.3  2003/02/08 20:55:09  pelle
 * Some documentation changes.
 * Major reorganization of code. The code is slowly being cleaned up in such a way that we can
 * get rid of the org.neuclear.utils package and split out the org.neuclear.xml.soap package.
 * Got rid of tons of unnecessary dependencies.
 * <p/>
 * Revision 1.2  2003/02/08 18:48:38  pelle
 * The Signature phase has been rewritten.
 * There now is a new Class called QuickEmbeddedSignature which is more in line with my original idea for this library.
 * It simply has a template of the xml and signs it in a standard way.
 * The original XMLSignature class is still used for verification and will in the future handle more thoroughly
 * all the various flavours of XMLSig.
 * XMLSecTools has got different flavours of canonicalize now. Including one where you can pass it a Canonicaliser to use.
 * Of the new Canonicalizer's are CanonicalizerWithComments, which I accidently left out of the last commit.
 * And CanonicalizerWithoutSignature which leaves out the Signature in the Canonicalization phase and is thus
 * a lot more efficient than the previous approach.
 * <p/>
 * Revision 1.1  2003/01/21 03:14:12  pelle
 * Mainly clean ups through out and further documentation.
 */
public final class SimpleXMLSigTest extends TestCase {
    public SimpleXMLSigTest(final String s) throws SecurityException, NoSuchAlgorithmException, CryptoException {
        super(s);
        rsa = CryptoTools.createTinyRSAKeyPair();
        dsa = CryptoTools.createTinyDSAKeyPair();
        signer = new TestCaseSigner();
        new File("target/testdata/homegrown").mkdirs();
    }

    private void assertValidEnvelopedSignature(Document doc) throws XMLSecurityException {
        try {
            XMLSignature sig = new EnvelopedSignature(doc.getRootElement());
        } catch (InvalidSignatureException e) {
            assertTrue("Signature Failed: " + e.getLocalizedMessage(), false);
        }
    }

    private void assertInvalidEnvelopedSignature(Document doc) throws XMLSecurityException {
        try {
            XMLSignature sig = new EnvelopedSignature(doc.getRootElement());
            assertTrue("Invalid Signature Verified", false);
        } catch (InvalidSignatureException e) {
            assertTrue("Signature Failed", true);
        }
    }

    private void assertValidEnvelopingSignature(Document doc) throws XMLSecurityException {
        try {
            XMLSignature sig = new DataObjectSignature(doc.getRootElement());
        } catch (InvalidSignatureException e) {
//            e.printStackTrace();
            assertTrue("Signature Failed: " + e.getLocalizedMessage(), false);
        }
    }

    private void assertValidExternalSignature(Document doc) throws XMLSecurityException {
        try {
            XMLSignature sig = new ExternalSignature(doc.getRootElement());
        } catch (InvalidSignatureException e) {
            assertTrue("Signature Failed: " + e.getLocalizedMessage(), false);
        }
    }

    public final void testEnvelopedUsignRSAKeyPair() throws DocumentException, XMLException, CryptoException {
        Document doc = DocumentHelper.parseText(TESTXML);
        final XMLSignature sig = new EnvelopedSignature(rsa, doc.getRootElement());
        final File outputFile = new File("target/testdata/homegrown/signature-enveloped-rsa.xml");
        XMLTools.writeFile(outputFile, doc);

        doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopedSignature(doc);
    }

    public final void testEnvelopedUsignDSAKeyPair()
            throws DocumentException, XMLException, CryptoException {
        assertTrue("Test if public key is really DSA", dsa.getPublic() instanceof DSAPublicKey);
        Document doc = DocumentHelper.parseText(TESTXML);
        final XMLSignature sig = new EnvelopedSignature(dsa, doc.getRootElement());

        final File outputFile = new File("target/testdata/homegrown/signature-enveloped-dsa.xml");
        XMLTools.writeFile(outputFile, doc);

        doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopedSignature(doc);
    }

    public final void testEnvelopingUsignRSAKeyPair() throws DocumentException, XMLException, CryptoException {
        Document doc = DocumentHelper.parseText(TESTXML);
        final XMLSignature sig = new DataObjectSignature(rsa, doc.getRootElement());
        final File outputFile = new File("target/testdata/homegrown/signature-enveloping-rsa.xml");
        XMLTools.writeFile(outputFile, sig.getElement());

        doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopingSignature(doc);
    }

    public final void testEnvelopingUsignDSAKeyPair() throws DocumentException, XMLException, CryptoException {
        Document doc = DocumentHelper.parseText(TESTXML);
        final XMLSignature sig = new DataObjectSignature(dsa, doc.getRootElement());
        final File outputFile = new File("target/testdata/homegrown/signature-enveloping-dsa.xml");
        XMLTools.writeFile(outputFile, sig.getElement());

        doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopingSignature(doc);
    }


    public final void testBadRSASignature() throws DocumentException, XMLException, CryptoException {
        final Document doc = DocumentHelper.parseText(TESTXML);

        final XMLSignature sig = new EnvelopedSignature(rsa, doc.getRootElement());
        assertValidEnvelopedSignature(doc);
        doc.getRootElement().addElement("BadElement");
        assertInvalidEnvelopedSignature(doc);

    }

    public final void testBadDSASignature()
            throws DocumentException, XMLException, CryptoException {
        final Document doc = DocumentHelper.parseText(TESTXML);

        final XMLSignature sig = new EnvelopedSignature(dsa, doc.getRootElement());
        assertValidEnvelopedSignature(doc);
        doc.getRootElement().addElement("BadElement");
        assertInvalidEnvelopedSignature(doc);
    }

    public final void testEnvelopedUsingSigner() throws DocumentException, XMLException, CryptoException, UserCancellationException {
        Document doc = DocumentHelper.parseText(TESTXML);
        final XMLSignature sig = new EnvelopedSignature("neu://test", signer, doc.getRootElement());
        final File outputFile = new File("target/testdata/homegrown/signature-enveloped-signer.xml");
        XMLTools.writeFile(outputFile, doc);

        doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopedSignature(doc);
    }

    public final void testEnvelopingUsingSigner() throws DocumentException, XMLException, CryptoException, UserCancellationException {
        Document doc = DocumentHelper.parseText(TESTXML);
        final XMLSignature sig = new DataObjectSignature("neu://test", signer, doc.getRootElement());
        final File outputFile = new File("target/testdata/homegrown/signature-enveloping-signer.xml");
        XMLTools.writeFile(outputFile, sig.getElement());

        doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopingSignature(doc);
    }

    public final void testComplexEnvelopedUsingSigner() throws DocumentException, XMLException, CryptoException, UserCancellationException {
        Document doc = DocumentHelper.parseText(COMPLEX_XML);
        final XMLSignature sig = new EnvelopedSignature("neu://test", signer, doc.getRootElement());
        final File outputFile = new File("target/testdata/homegrown/signature-complex-enveloped-signer.xml");
        XMLTools.writeFile(outputFile, doc);

        doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopedSignature(doc);
    }

    public final void testComplexEnvelopingUsingSigner() throws DocumentException, XMLException, CryptoException, UserCancellationException {
        Document doc = DocumentHelper.parseText(COMPLEX_XML);
        final XMLSignature sig = new DataObjectSignature("neu://test", signer, doc.getRootElement());
        final File outputFile = new File("target/testdata/homegrown/signature-complex-enveloping-signer.xml");
        XMLTools.writeFile(outputFile, sig.getElement());

        doc = XMLTools.loadDocument(outputFile);
        assertValidEnvelopingSignature(doc);
    }

    public final void testExternalSignatureUsingSigner() throws DocumentException, XMLException, CryptoException, UserCancellationException {
        final XMLSignature sig = new ExternalSignature("neu://test", signer, "http://www.w3.org/TR/2000/WD-xml-c14n-20001011");
        final File outputFile = new File("target/testdata/homegrown/signature-external-signer.xml");
        XMLTools.writeFile(outputFile, sig.getElement());

        Document doc = XMLTools.loadDocument(outputFile);
        assertValidExternalSignature(doc);
    }

    public final void testExternalDSASignature() throws DocumentException, XMLException, CryptoException, UserCancellationException {
        final XMLSignature sig = new ExternalSignature(dsa, "http://www.w3.org/TR/2000/WD-xml-c14n-20001011");
        final File outputFile = new File("target/testdata/homegrown/signature-external-dsa.xml");
        XMLTools.writeFile(outputFile, sig.getElement());

        Document doc = XMLTools.loadDocument(outputFile);
        assertValidExternalSignature(doc);
    }

    public final void testExternalRSASignature() throws DocumentException, XMLException, CryptoException, UserCancellationException {
        final XMLSignature sig = new ExternalSignature(rsa, "http://www.w3.org/TR/2000/WD-xml-c14n-20001011");
        final File outputFile = new File("target/testdata/homegrown/signature-external-rsa.xml");
        XMLTools.writeFile(outputFile, sig.getElement());

        Document doc = XMLTools.loadDocument(outputFile);
        assertValidExternalSignature(doc);
    }

    public final void testExampleEnvelopedForOverviewDoc() throws NoSuchAlgorithmException, DocumentException, XMLSecurityException {
        KeyPair kp = CryptoTools.createTinyRSAKeyPair();

        Document doc = DocumentHelper.parseText("<test><test2/></test>");
        Element elem = doc.getRootElement();

        EnvelopedSignature envsig = new EnvelopedSignature(kp, elem);
//        System.out.println(doc.asXML());

        try {
            EnvelopedSignature verifid = new EnvelopedSignature(elem);
        } catch (InvalidSignatureException e) {
            System.err.println("Invalid Signature");
        }
    }

    public final void testExampleEnvelopingForOverviewDoc() throws NoSuchAlgorithmException, DocumentException, XMLSecurityException {
        KeyPair kp = CryptoTools.createTinyRSAKeyPair();

        Document doc = DocumentHelper.parseText("<test><test2/></test>");
        Element elem = doc.getRootElement();

        DataObjectSignature datasig = new DataObjectSignature(kp, elem);
        Element sigelem = datasig.getElement();
//        System.out.println(sigelem.asXML());

        try {
            DataObjectSignature verified = new DataObjectSignature(sigelem);
        } catch (InvalidSignatureException e) {
            System.err.println("Invalid Signature");
        }
    }

    public final void testLameBenchmarkVerification() throws DocumentException, XMLSecurityException, InvalidSignatureException {
        Document doc = DocumentHelper.parseText(TESTXML);
        final XMLSignature sig = new EnvelopedSignature(rsa, doc.getRootElement());
        String raw = doc.asXML();
        // Once to initialize the gc
        Document signed = DocumentHelper.parseText(raw);
        new EnvelopedSignature(signed.getRootElement());
        System.out.println("Starting SAX benchmarks");
        long start = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            signed = DocumentHelper.parseText(raw);
            new EnvelopedSignature(signed.getRootElement());
        }
        long duration = System.currentTimeMillis() - start;
        System.out.println(duration + "ms");


    }

    public final void testLameBenchmarkVerificationXPP3() throws Exception {
        Document doc = DocumentHelper.parseText(TESTXML);
        XPP3Reader xp = new XPP3Reader();

        final XMLSignature sig = new EnvelopedSignature(rsa, doc.getRootElement());
        String raw = doc.asXML();
        // Once to initialize the gc
        char[] chars = raw.toCharArray();
        Document signed = xp.read(chars);
        new EnvelopedSignature(signed.getRootElement());
        System.out.println("Starting XPP3 benchmarks");
        long start = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            signed = xp.read(chars);
            new EnvelopedSignature(signed.getRootElement());
        }
        long duration = System.currentTimeMillis() - start;
        System.out.println(duration + "ms");


    }

    public final void testLameBenchmarkVerificationXPP2() throws Exception {
        Document doc = DocumentHelper.parseText(TESTXML);
        XPPReader xp = new XPPReader();

        final XMLSignature sig = new EnvelopedSignature(rsa, doc.getRootElement());
        String raw = doc.asXML();
        // Once to initialize the gc
        char[] chars = raw.toCharArray();
        Document signed = xp.read(chars);
        new EnvelopedSignature(signed.getRootElement());
        System.out.println("Starting XPP2 benchmarks");
        long start = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            signed = xp.read(chars);
            new EnvelopedSignature(signed.getRootElement());
        }
        long duration = System.currentTimeMillis() - start;
        System.out.println(duration + "ms");


    }

    private final KeyPair rsa;
    private final KeyPair dsa;
    private final Signer signer;
    final static String TESTXML = "<test><test2></test2></test>";
    final static String COMPLEX_XML = "<test xmlns=\"http://talk.org\"><test2></test2></test>";

}
