package org.neuclear.xml.xmlsec;
/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Feb 3, 2003
 * Time: 6:54:20 AM
 * $Id: SignatureTests.java,v 1.1 2003/11/11 16:33:32 pelle Exp $
 * $Log: SignatureTests.java,v $
 * Revision 1.1  2003/11/11 16:33:32  pelle
 * Initial revision
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
import org.neuclear.xml.xmlsec.XMLSecTools;
import org.neuclear.commons.RegexFileNameFilter;
import org.neuclear.commons.NeuClearException;

import java.io.*;

public class SignatureTests extends TestCase {
    public SignatureTests(String s) {
        super(s);
        reader=new SAXReader(false);
        reader.setMergeAdjacentText(false);
        reader.setStripWhitespaceText(false);
        reader.setIncludeExternalDTDDeclarations(true);
        reader.setIncludeInternalDTDDeclarations(true);
    }

    public void testHomeGrown() throws IOException, DocumentException, NeuClearException {
        runDirectoryTest("src/testdata/homegrown");
    }

    public void testMerlin23() throws IOException, DocumentException, NeuClearException {
        runDirectoryTest("src/testdata/merlin-xmldsig-twenty-three");//,"signature-enveloping-dsa\\.xml");
    }
    public void testPhaos() throws IOException, DocumentException, NeuClearException {
//        runDirectoryTest("src/testdata/phaos-xmldsig-two");
    }

    public void runDirectoryTest(String path) throws DocumentException, IOException, FileNotFoundException, NeuClearException {
        runDirectoryTest(path,null);
    }

    public void runDirectoryTest(String path,String regex) throws DocumentException, IOException, FileNotFoundException, NeuClearException {
        File dir=new File(path);
        if (!dir.exists()) {
            System.out.println("Doesnt exist");
            return;
        }
        FilenameFilter filter;
        if (regex==null)
            filter=new FilenameFilter(){
                public boolean accept(File dirf, String name) {
                    return name.endsWith(".xml");
                }
            };
        else filter=new RegexFileNameFilter(regex);

        File xmlfiles[]=dir.listFiles(filter);
        System.out.println("There are "+xmlfiles.length+" files in the directory");
        for (int i = 0; i < xmlfiles.length; i++) {

            File xmlfile = xmlfiles[i];
            System.out.print("Testing file: "+xmlfile.getName()+"... ");
            Document doc=reader.read(xmlfile);
            System.out.print("root element: "+doc.getRootElement().getQualifiedName()+" ...");
            try {
                if(XMLSecTools.verifySignature(doc.getRootElement()))
                   System.out.println("Verified");
                else
                    System.out.println("FAILED");
            } catch (Exception e) {
                    System.out.println("ERROR "+e.getMessage());
//                e.printStackTrace();  //To change body of catch statement use Options | File Templates.
            }
        }


    }

    SAXReader reader;

}
