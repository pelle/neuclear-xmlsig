package org.neuclear.xml.transforms;


/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 21, 2003
 * Time: 3:12:00 PM
 * $Id: XPathTransformTest.java,v 1.2 2003/11/21 04:44:31 pelle Exp $
 * $Log: XPathTransformTest.java,v $
 * Revision 1.2  2003/11/21 04:44:31  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.1.1.1  2003/11/11 16:33:31  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.2  2003/02/22 16:54:30  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.1  2003/02/01 01:48:26  pelle
 * Fixed the XPath Transform.
 * Has the beginning of a processing framework for the Reference class.
 *
 * Revision 1.1  2003/01/21 22:01:44  pelle
 * Added a bunch of test cases for Transforms.
 * Also several new transforms are there.
 * I have a feeling I didn't think this through, so dont use the Transform bit yet.
 * NB. None of it is used yet by the actual signing process so dont worry.
 *
 */

import org.dom4j.*;

import java.util.Iterator;

public final class XPathTransformTest extends AbstractTransformTest {
    public XPathTransformTest(final String s) {
        super(s);
    }

    public final Transform createTransform() {
        return new XPathTransform("/test");
    }

    public final Element getExpectedResult() throws DocumentException {
        return DocumentHelper.parseText("<test/>").getRootElement();
    }

    public final void testXPathFun() throws DocumentException {
        doc=DocumentHelper.parseText("<test><test2><test one=\"1\">text</test></test2></test>");
        System.out.println("testXPathFun");
//        System.out.println(tr.transformNode(getTestElement()).asXML());
//        listXPath("test");
//        listXPath("/test");
//        listXPath("//test");
//        listXPath("./test");
//        listXPath("//.");
//        listXPath("(//. | //@* | //namespace::*)");
//


    }
    public final void testNoDoc() throws DocumentException {
        final Element elem=DocumentHelper.createElement("test");
        assertNotNull(tr.transformNode(elem));
    }

    private void listXPath(final String expr) {
        System.out.println("Testing: "+expr);
        final XPath xp=DocumentHelper.createXPath(expr);
        final Iterator iter=xp.selectNodes(doc).iterator();

        while (iter.hasNext()) {
            final Node node = (Node) iter.next();
            System.out.println("Matched: "+node.toString());
        }
    }
    Document doc;
}
