package org.neuclear.xml.transforms;


/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 21, 2003
 * Time: 3:12:00 PM
 * $Id: DropSignatureTransformTest.java,v 1.2 2003/11/21 04:44:31 pelle Exp $
 * $Log: DropSignatureTransformTest.java,v $
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
 * Revision 1.2  2003/02/11 14:50:26  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
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

import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;

public final class DropSignatureTransformTest extends AbstractTransformTest {
    public DropSignatureTransformTest(final String s) {
        super(s);
    }

    public final Transform createTransform() {
        return new DropSignatureTransform();
    }

    public final Element getTestElement() {
        try {
            return DocumentHelper.parseText(TESTELEMENT).getRootElement();
        } catch (DocumentException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
            return null;
        }
    }

    public final Element getExpectedResult() {
        try {
            return DocumentHelper.parseText(TESTRESULT).getRootElement();
        } catch (DocumentException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
            return null;
        }
    }

    private static final String TESTELEMENT="<test><test2/><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/></test>";
    private static final String TESTRESULT="<test><test2/></test>";
}
