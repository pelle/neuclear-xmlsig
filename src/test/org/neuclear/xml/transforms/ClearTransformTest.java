package org.neuclear.xml.transforms;

import org.dom4j.DocumentException;
import org.dom4j.Element;

/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Jan 21, 2003
 * Time: 3:12:00 PM
 * $Id: ClearTransformTest.java,v 1.2 2003/11/21 04:44:31 pelle Exp $
 * $Log: ClearTransformTest.java,v $
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
 * Revision 1.3  2003/02/11 14:50:25  pelle
 * Trying onemore time. Added the benchmarking code.
 * Now generates DigestValue and optionally adds KeyInfo to Signature.
 *
 * Revision 1.2  2003/02/01 01:48:26  pelle
 * Fixed the XPath Transform.
 * Has the beginning of a processing framework for the Reference class.
 *
 * Revision 1.1  2003/01/21 22:01:43  pelle
 * Added a bunch of test cases for Transforms.
 * Also several new transforms are there.
 * I have a feeling I didn't think this through, so dont use the Transform bit yet.
 * NB. None of it is used yet by the actual signing process so dont worry.
 *
 */
public final class ClearTransformTest extends AbstractTransformTest {
    public ClearTransformTest(final String s) {
        super(s);
    }

    public final Transform createTransform() {
        return new ClearTransform();
    }

    public final Element getExpectedResult() throws DocumentException {
        return getTestElement();
    }
}
