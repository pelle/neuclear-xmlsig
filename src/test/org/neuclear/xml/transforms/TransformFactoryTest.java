package org.neuclear.xml.transforms;

/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 21, 2003
 * Time: 3:28:14 PM
 * $Id: TransformFactoryTest.java,v 1.1 2003/11/11 16:33:31 pelle Exp $
 * $Log: TransformFactoryTest.java,v $
 * Revision 1.1  2003/11/11 16:33:31  pelle
 * Initial revision
 *
 * Revision 1.3  2003/02/11 14:50:26  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
 *
 * Revision 1.2  2003/02/01 01:48:26  pelle
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

import junit.framework.TestCase;
import org.dom4j.Element;
import org.neuclear.xml.xmlsec.XMLSecTools;

public class TransformFactoryTest extends TestCase{
    public TransformFactoryTest(String s) {
        super(s);
        {
            ClearTransform.class.toString();
            XPathTransform.class.toString();
            OpaqueTransform.class.toString();
        }
    }
    public void testCreateFromAlgorithmName() throws XMLTransformNotFoundException {
        assertNotNull(TransformerFactory.make("uri:neuclear-test-clear-transform"));
        assertNotNull(TransformerFactory.make("uri:neuclear-test-opaque-transform"));
        try {
            TransformerFactory.make("uri:neuclear-test-non-existent");
            assertTrue("TransformerFactory incorrectly did not throw an exception",true);
        } catch (XMLTransformNotFoundException e) {
            assertTrue("TransformerFactory correctly throw an exception",true);
        }

    }
    public void testCreateFromElement() throws XMLTransformNotFoundException {
        Element clear=XMLSecTools.createElementInSignatureSpace("Transform");
        clear.addAttribute("Algorithm","uri:neuclear-test-clear-transform");
        assertNotNull(TransformerFactory.make(clear));

        Element opaque=XMLSecTools.createElementInSignatureSpace("Transform");
        opaque.addAttribute("Algorithm","uri:neuclear-test-opaque-transform");
        assertNotNull(TransformerFactory.make(opaque));

        Element dud=XMLSecTools.createElementInSignatureSpace("Transform");
        dud.addAttribute("Algorithm","uri:neuclear-test-non-existent");
        try {
            TransformerFactory.make(dud);
            assertTrue("TransformerFactory incorrectly did not throw an exception",true);
        } catch (XMLTransformNotFoundException e) {
            assertTrue("TransformerFactory correctly throw an exception",true);
        }


    }
}
