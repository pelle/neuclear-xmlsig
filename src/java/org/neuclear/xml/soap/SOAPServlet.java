/* $Id: SOAPServlet.java,v 1.3 2003/11/24 23:33:15 pelle Exp $
 * $Log: SOAPServlet.java,v $
 * Revision 1.3  2003/11/24 23:33:15  pelle
 * More Cactus unit testing going on.
 *
 * Revision 1.2  2003/11/21 04:44:30  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.1.1.1  2003/11/11 16:33:22  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.3  2003/11/09 03:27:09  pelle
 * More house keeping and shuffling about mainly pay
 *
 * Revision 1.2  2003/09/26 23:52:47  pelle
 * Changes mainly in receiver and related fun.
 * First real neuclear stuff in the payment package. Added TransferContract and AssetControllerReceiver.
 *
 * Revision 1.1  2003/01/18 18:12:31  pelle
 * First Independent commit of the Independent XML-Signature API for NeuDist.
 *
 * Revision 1.8  2002/12/17 21:41:02  pelle
 * First part of refactoring of SignedNamedObject and SignedObject Interface/Class parings.
 *
 * Revision 1.7  2002/12/17 20:34:44  pelle
 * Lots of changes to core functionality.
 * First of all I've refactored most of the Resolving and verification code. I have a few more things to do
 * on it before I'm happy.
 * There is now a NSResolver class, which handles all the namespace resolution. I took most of the functionality
 * for this out of SignedNamedObject.
 * Then there is the veriifer, which verifies a given SignedNamedObject using the NSResolver.
 * This has simplified the SignedNamedObject classes drastically, leaving them as mainly data objects, which is what they
 * should be.
 * I have also gone around and tightened up security on many different classes, making clases and/or methods final where appropriate.
 * NSCache now operates using http://www.waterken.com's fantastic ADT collections library.
 * Something important has been added, which is a SignRequest named object. This signed object, embeds an unsigned
 * named object for signing by an end users' signing service.
 * Now were almost ready to start seriously implementing AssetIssuers and Transfers, which will be the most important
 * part of the framework.
 *
 * Revision 1.6  2002/10/03 01:51:58  pelle
 * Bunch of smaller fixes for bugs found during deployment.
 * Also a bit more documentation.
 * I'm happy with this being called rev. 0.4
 *
 * Revision 1.5  2002/10/02 21:03:45  pelle
 * Major Commit
 * I completely redid the namespace resolving code.
 * It now works correctly with the new store attribute of the namespace
 * And can correctly work out the location of a namespace file
 * by hierarchically signing it.
 * I have also included several top level namespaces and finalised
 * the root namespace.
 * In short all of the above means that we can theoretically call
 * Neubia live now. (Well on my first deployment anyway).
 * There is a new CommandLineSigner utility class which creates and signs
 * namespaces using standard java keystores.
 * I'm now working on updating the documentation, so other people
 * than me might have a chance at using it.
 *
 * Revision 1.4  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 */
package org.neuclear.xml.soap;

/**
 * @author pelleb
 * @version $Revision: 1.3 $
 */

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class SOAPServlet extends XMLInputStreamServlet {

    protected abstract Element handleSOAPRequest(Element request, String soapAction) throws SOAPException;

    protected final void handleInputStream(final InputStream is, final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        try {
            final SAXReader reader = new SAXReader();
            final Document doc = reader.read(is);
//            System.out.println("RECEIVED:" + doc.asXML());
//            System.out.println("NEUDIST: SOAP Post Request to " + this.getClass().getName());
            final Element bodyElement = doc.getRootElement().element(SOAPTools.createEnvelopeQName());
            //TODO: Check for null
            final Element requestElement = (Element) bodyElement.elements().get(0);
            if (requestElement == null) {
//                System.out.println("NEUDIST: SOAP Request was invalid");
//                System.out.println(doc.asXML());
                response.sendError(500, "NEUDIST: SOAP Request was invalid");
            }
            Element respElement = null;
            try {
                respElement = handleSOAPRequest(requestElement, request.getHeader("SOAPAction"));
            } catch (SOAPException e) {
                respElement = DocumentHelper.createElement("Exception");
                respElement.addElement("Message").addText(e.getMessage());
            }
            if (respElement == null)
                respElement = DocumentHelper.createElement("Response").addText("OK");
            if (respElement.getDocument() == null)
                DocumentHelper.createDocument(respElement);
            response.setContentType("text/xml");
            final OutputStream out = response.getOutputStream();


            final XMLWriter writer = new XMLWriter(out, OutputFormat.createCompactFormat());
            writer.write(respElement);
            out.close();
        } catch (DocumentException e) {
//            System.out.println("NeuDist: Exception in SOAP Request");
            e.printStackTrace(System.out);
            response.sendError(500, e.getMessage());
        }
    }

}
