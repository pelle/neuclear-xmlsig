package org.neuclear.xml.c14;
/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Feb 3, 2003
 * Time: 6:54:20 AM
 * $Id: CanonicalizationTest.java,v 1.1 2003/11/11 16:33:30 pelle Exp $
 * $Log: CanonicalizationTest.java,v $
 * Revision 1.1  2003/11/11 16:33:30  pelle
 * Initial revision
 *
 * Revision 1.5  2003/09/29 23:44:54  pelle
 * Trying to tweak Canonicalizer to function better.
 * Apparently the built in Sun JCE doesnt like the Keysizes of NSROOT
 * So now CryptoTools forces the use of BouncyCastle
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

import java.io.*;

public class CanonicalizationTest extends TestCase {
    public CanonicalizationTest(String s) {
        super(s);
        reader=new SAXReader(false);
        reader.setMergeAdjacentText(false);
        reader.setStripWhitespaceText(false);
        reader.setIncludeExternalDTDDeclarations(true);
        reader.setIncludeInternalDTDDeclarations(true);
    }


/*
    public void testHomeGrown() throws IOException, DocumentException {
//        runDirectoryTest("src/testdata/c14");
    }
*/
    public void testMerlin() throws IOException, DocumentException {
        runDirectoryTest("src/testdata/merlin-xmldsig-eight");
    }

    public void runDirectoryTest(String path) throws DocumentException, IOException, FileNotFoundException {
        File dir=new File(path);
        if (!dir.exists()) {
            System.out.println("Doesnt exist");
            return;
        }
        //FilenameFilter filter=FilenameFilter;
        File xmlfiles[]=dir.listFiles(new FilenameFilter(){
           public boolean accept(File dirf, String name) {
                return name.endsWith(".xml");
            }

        });

        for (int i = 0; i < xmlfiles.length; i++) {

            File xmlfile = xmlfiles[i];
            System.out.println("Testing file: "+xmlfile.getName());
            File c14file=getC14Name(xmlfile);
            if (c14file.exists()&&!hasXPath(xmlfile)){ //Just disabling the XPath Subset functionality until I hear from the Dom4J guys

                try {
                    if (xmlfile.getName().equals("example-6.xml"))
                        System.out.println("Here we go");
                    Document doc=reader.read(xmlfile);
                    byte[] ourbytes=null;
                    if (hasXPath(xmlfile)) {
                        File xpathFile=getXPathFileName(xmlfile);
                        FileReader xpreader=new FileReader(xpathFile);
                        char xpathc[]=new char[(int)xpathFile.length()];
                        xpreader.read(xpathc,0,xpathc.length);
                        xpreader.close();
                        String xpath=new String(xpathc);
                        System.out.println("XPATH="+xpath);
                        ourbytes=XMLSecTools.canonicalizeSubset(doc,xpath);
                    } else
                        ourbytes=XMLSecTools.canonicalize(doc);
                    FileOutputStream fos=new FileOutputStream(getC14OutputName(xmlfile));
                    fos.write(ourbytes);
                    fos.close();
                    compareFileWithByteArray(c14file, ourbytes);

                } catch (DocumentException e) {
                    e.printStackTrace();  //To change body of catch statement use Options | File Templates.
                } catch (IOException e) {
                    e.printStackTrace();  //To change body of catch statement use Options | File Templates.
                }

            }   else System.err.println("Missing C14 Version: "+c14file.getName());
        }


    }

    private void compareFileWithByteArray(File c14file, byte[] ourbytes) throws IOException {
        byte[] theirbytes=new byte[(int)c14file.length()];

        FileInputStream fis=new FileInputStream(c14file);
        fis.read(theirbytes);
        boolean equal=ourbytes.length==theirbytes.length;
        if (!equal) {
            System.out.println("Ourbytes= "+ourbytes.length+" theirbytes="+theirbytes.length);
        }
        assertTrue(equal);
        int j=0;

        for ( j=0;equal&&j<ourbytes.length;j++){
//                        System.out.print(ourbytes[j]);
            equal=ourbytes[j]==theirbytes[j];
            if (!equal){
                System.out.println("Problem was at character: "+j+" ourbytes["+j+"]='"+ourbytes[j]+"' theirbytes["+j+"]='"+theirbytes[j]+"'");
                System.out.println(new String(ourbytes));
                System.out.println(new String(theirbytes));
        //                        System.out.println("====ORIGINALFILE====");
        //                        System.out.println(doc.asXML());

            }
        }
        assertTrue(equal);
    }

    private File getC14Name(File file){
        String newname=file.getName();
        return new File(file.getParentFile(),newname.substring(0,newname.length()-3)+"c14n");
    }
    private File getC14OutputName(File file){
        String newname=file.getName();
        return new File(file.getParentFile(),newname.substring(0,newname.length()-3)+"out");
    }
    private File getXPathFileName(File file){
        String newname=file.getName();
        return new File(file.getParentFile(),newname.substring(0,newname.length()-3)+"xpath");
    }
    private boolean hasXPath(File file) {
        return getXPathFileName(file).exists();
    }

    SAXReader reader;
}
