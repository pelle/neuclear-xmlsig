package org.neuclear.xml.transforms;

import junit.framework.TestCase;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.Node;

/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 21, 2003
 * Time: 2:56:19 PM
 * $Id: AbstractTransformTest.java,v 1.1 2003/11/11 16:33:31 pelle Exp $
 * $Log: AbstractTransformTest.java,v $
 * Revision 1.1  2003/11/11 16:33:31  pelle
 * Initial revision
 *
 * Revision 1.3  2003/02/22 16:54:30  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.2  2003/02/11 14:50:25  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
 *
 * Revision 1.1  2003/02/07 21:15:19  pelle
 * Much improved Canonicalizer and Test Suite.
 * I've added the merlin-xmldsig-eight Canonicalization test suite.
 * All tests still dont work.
 *
 */
public abstract class AbstractTransformTest extends TestCase {
    public AbstractTransformTest(String s) {
        super(s);
        tr=createTransform();
    }
    public abstract Transform createTransform();

    public Element getExpectedResult() throws DocumentException {
        return null;
    }

    public Element getTestElement() throws DocumentException {
//        Element elem=DocumentHelper.createElement("test");
//        elem.addElement("test2").addText("Hello");
        return DocumentHelper.parseText("<test><test2>hello</test2></test>").getRootElement();
    }

    public void testTransformElement() throws DocumentException {
        Object result=tr.transformNode(getTestElement());
        Node expected=getExpectedResult();
       if(expected==null)
          assertNull("The Transform did not return null as expected",result);
       else {
           assertNotNull("The Transform returned a null",result);
           assertEquals(((Element)result).asXML(),expected.asXML());
       }
    }

    protected Transform tr;
}
