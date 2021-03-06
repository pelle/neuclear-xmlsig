package org.neuclear.xml.xmlsec;

import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.passphraseagents.swing.SwingAgent;
import org.neuclear.commons.crypto.signers.BrowsableSigner;
import org.neuclear.commons.crypto.signers.InvalidPassphraseException;
import org.neuclear.commons.crypto.signers.TestCaseSigner;

/*
$Id: InteractiveXMLSignature.java,v 1.4 2004/05/11 15:38:24 pelle Exp $
$Log: InteractiveXMLSignature.java,v $
Revision 1.4  2004/05/11 15:38:24  pelle
Removed a few compilation errors

Revision 1.3  2004/04/20 23:32:54  pelle
All unit tests (junit and cactus) work. The AssetControllerServlet is operational.

Revision 1.2  2004/04/12 15:28:00  pelle
Added Hibernate and Prevalent tests for Currency Controllers

Revision 1.1  2004/04/07 17:22:23  pelle
Added support for the new improved interactive signing model. A new Agent is also available with SwingAgent.
The XMLSig classes have also been updated to support this.

*/

/**
 * User: pelleb
 * Date: Apr 7, 2004
 * Time: 12:07:19 PM
 */
public class InteractiveXMLSignature {
    public static void main(String args[]) {
        try {
            BrowsableSigner signer = new TestCaseSigner(new SwingAgent());

            final Element element = DocumentHelper.parseText(COMPLEX_XML).getRootElement();
            XMLSignature sig = new EnvelopedSignature(signer, element);

            System.out.println(element.asXML());
            System.exit(0);
        } catch (InvalidPassphraseException e) {
            e.printStackTrace();
        } catch (XMLSecurityException e) {
            e.printStackTrace();
        } catch (DocumentException e) {
            e.printStackTrace();
        } catch (UserCancellationException e) {
            e.printStackTrace();
        }

    }

    private InteractiveXMLSignature() {
    };
    final static String COMPLEX_XML = "<test xmlns=\"http://talk.org\"><test2></test2></test>";

}
