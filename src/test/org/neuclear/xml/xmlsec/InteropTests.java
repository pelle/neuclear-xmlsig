package org.neuclear.xml.xmlsec;

/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Feb 3, 2003
 * Time: 6:54:20 AM
 * $Id: InteropTests.java,v 1.2 2004/03/19 23:38:25 pelle Exp $
 * $Log: InteropTests.java,v $
 * Revision 1.2  2004/03/19 23:38:25  pelle
 * I now know the problem is in the Reference element
 *
 * Revision 1.1  2004/03/19 22:21:51  pelle
 * Changes in the XMLSignature class, which is now Abstract there are currently 3 implementations for:
 * - Enveloped
 * - DataObjects - (Enveloping)
 * - Any for interop testing mainly.
 *
 * Revision 1.5  2004/02/19 00:28:00  pelle
 * Discovered several incompatabilities with the xmlsig implementation. Have been working on getting it working.
 * Currently there is still a problem with enveloping signatures and it seems enveloped signatures done via signers.
 *
 * Revision 1.4  2004/01/14 17:07:59  pelle
 * KeyInfo containing X509Certificates now work correctly.
 * 10 out of 16 of merlin's tests now work. The missing ones are largely due to key resolution issues. (Read X509)
 *
 * Revision 1.3  2004/01/14 16:34:27  pelle
 * New model of references and signatures now pretty much works.
 * I am still not 100% sure on the created enveloping signatures. I need to do more testing.
 *
 * Revision 1.2  2003/11/21 04:44:31  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.1.1.1  2003/11/11 16:33:32  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.6  2003/10/21 22:30:33  pelle
 * Renamed NeudistException to NeuClearException and moved it to org.neuclear.commons where it makes more sense.
 * Unhooked the XMLException in the xmlsig library from NeuClearException to make all of its exceptions an independent hierarchy.
 * Obviously had to perform many changes throughout the code to support these changes.
 *
 * Revision 1.5  2003/02/24 14:20:02  pelle
 * Minor adjustments
 *
 * Revision 1.4  2003/02/23 23:21:47  pelle
 * Yeah. We figured it out. We now have interop.
 * Granted not on all features as yet, but definitely on simple signatures.
 * I'm checking in Ramses' fix to QuickEmbeddedSignature and my fixes to the verification process.
 *
 * Revision 1.3  2003/02/22 23:19:10  pelle
 * Additional fixes to the encoding problem.
 *
 * Revision 1.2  2003/02/22 16:54:30  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.1  2003/02/21 22:48:19  pelle
 * New Test Infrastructure
 * Added test keys in src/testdata/keys
 * Modified tools to handle these keys
 *
 * Revision 1.4  2003/02/11 14:50:25  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
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
 * Revision 1.2  2003/02/07 22:33:48  pelle
 * Compliance mostly working.
 * Merlin's Example 7 hasn't been implemented, but mainly because we havent written the test case yet.
 * A few of the example c14n files had trailing new lines. I'm not sure what the spec says about that, but I
 * got rid of them as my implementation doesnt support those. Who is right?
 * Example 4 has problems with the final element. This seems to be causing problems for lots of people.
 * To workaround it, I've removed the offending lines from all the files.
 * TBH I dont understand whats going on with it. Will put it on the back burner and come back.
 *
 * Revision 1.1  2003/02/07 21:15:19  pelle
 * Much improved Canonicalizer and Test Suite.
 * I've added the merlin-xmldsig-eight Canonicalization test suite.
 * All tests still dont work.
 *
 */

import junit.framework.TestCase;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;
import org.neuclear.commons.NeuClearException;
import org.neuclear.commons.RegexFileNameFilter;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;

public final class InteropTests extends TestCase {
    public InteropTests(final String s) {
        super(s);
        reader = new SAXReader(false);
        reader.setMergeAdjacentText(false);
        reader.setStripWhitespaceText(false);
        reader.setIncludeExternalDTDDeclarations(true);
        reader.setIncludeInternalDTDDeclarations(true);
    }

//    public final void testHomeGrown() throws IOException, DocumentException, NeuClearException {
//        runDirectoryTest("src/testdata/homegrown");
//    }

    public final void testMerlin23() throws IOException, DocumentException, NeuClearException {
        runDirectoryTest("src/testdata/merlin-xmldsig-twenty-three", 11);//,"signature-enveloping-dsa\\.xml");
    }

    public final void testPhaos() throws IOException, DocumentException, NeuClearException {
        runDirectoryTest("src/testdata/phaos-xmldsig-two", 0);
    }

    public final void runDirectoryTest(final String path, final int pass) throws DocumentException, IOException, FileNotFoundException, NeuClearException {
        runDirectoryTest(path, null, pass);
    }

    public final void runDirectoryTest(final String path, final String regex, final int pass) throws DocumentException, IOException, FileNotFoundException, NeuClearException {
        final File dir = new File(path);
        if (!dir.exists()) {
            System.out.println("Doesnt exist");
            return;
        }
        final FilenameFilter filter;
        if (regex == null)
            filter = new FilenameFilter() {
                public boolean accept(final File dirf, final String name) {
                    return name.endsWith(".xml");
                }
            };
        else
            filter = new RegexFileNameFilter(regex);

        final File[] xmlfiles = dir.listFiles(filter);
        System.out.println("There are " + xmlfiles.length + " files in the directory");
        int errors = 0;
        int i = 0;
        for (i = 0; i < xmlfiles.length; i++) {

            final File xmlfile = xmlfiles[i];
            System.out.print("Testing file: " + xmlfile.getName() + "... ");
            final Document doc = reader.read(xmlfile);
            System.out.print("root element: " + doc.getRootElement().getQualifiedName() + " ...");
            try {
                if (verifySignature(doc))
                    System.out.println("Verified");
                else
                    System.out.println("FAILED: " + (errors++));
            } catch (Exception e) {
                System.out.println("ERROR: " + (errors++) + e.getMessage());
                e.printStackTrace();  //To change body of catch statement use Options | File Templates.
            }
        }
        System.out.println(errors + " out of " + i + " documents failed");
        assertTrue("Acheived Pass rate: ", errors <= pass);


    }

    private boolean verifySignature(Document doc) throws XMLSecurityException {
        try {
            new AnyXMLSignature(doc.getRootElement());
            return true;
        } catch (InvalidSignatureException e) {
            return false;
        }
    }

    final SAXReader reader;

}
