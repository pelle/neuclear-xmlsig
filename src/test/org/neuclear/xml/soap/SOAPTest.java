/*
 * Created by IntelliJ IDEA.
 * User: pelleb
 * Date: Oct 1, 2002
 * Time: 9:54:52 PM
 * To change template for new class use 
 * Code Style | Class Templates options (Tools | IDE Options).
 */
package org.neuclear.xml.soap;

import junit.framework.TestCase;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.neuclear.commons.NeuClearException;

public final class SOAPTest extends TestCase {
    public SOAPTest(final String name) {
        super(name);
    }



    public final void testGetQuote() throws NeuClearException {
        final Element getQuote = DocumentHelper.createElement(DocumentHelper.createQName("getQuote", DocumentHelper.createNamespace("ns1", "urn:xmethods-delayed-quotes")));
        getQuote.addElement(DocumentHelper.createQName("symbol", DocumentHelper.createNamespace("ns1", "urn:xmethods-delayed-quotes"))).addText("MSFT");
//            Element response=soapRequest("http://localhost/cgi-bin/xmlenv",getQuote,"urn:xmethods-delayed-quotes#getQuote");
        final Element response = SOAPTools.soapRequestElement("http://66.28.98.121:9090/soap", getQuote, "urn:xmethods-delayed-quotes#getQuote");
        System.out.println("testGetQuote:");
        System.out.println(response.asXML());
        assertNotNull(response);
        assertEquals(response.getName(), "getQuoteResponse");
    }

}
