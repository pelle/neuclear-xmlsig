/* $Id: SOAPTools.java,v 1.4 2003/11/24 23:33:15 pelle Exp $
 * $Log: SOAPTools.java,v $
 * Revision 1.4  2003/11/24 23:33:15  pelle
 * More Cactus unit testing going on.
 *
 * Revision 1.3  2003/11/21 04:44:30  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.2  2003/11/19 23:33:16  pelle
 * Signers now can generatekeys via the generateKey() method.
 * Refactored the relationship between SignedNamedObject and NamedObjectBuilder a bit.
 * SignedNamedObject now contains the full xml which is returned with getEncoded()
 * This means that it is now possible to further send on or process a SignedNamedObject, leaving
 * NamedObjectBuilder for its original purposes of purely generating new Contracts.
 * NamedObjectBuilder.sign() now returns a SignedNamedObject which is the prefered way of processing it.
 * Updated all major interfaces that used the old model to use the new model.
 *
 * Revision 1.1.1.1  2003/11/11 16:33:23  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.9  2003/11/10 17:42:18  pelle
 * The AssetController interface has been more or less finalized.
 * CurrencyController fully implemented
 * AssetControlClient implementes a remote client for communicating with AssetControllers
 *
 * Revision 1.8  2003/11/09 03:27:09  pelle
 * More house keeping and shuffling about mainly pay
 *
 * Revision 1.7  2003/11/08 22:21:08  pelle
 * Fixed a few things with regards to the SOAPTools class.
 *
 * Revision 1.6  2003/11/08 01:40:20  pelle
 * WARNING this rev is majorly unstable and will almost certainly not compile.
 * More major refactoring in neuclear-pay.
 * Got rid of neuclear-ledger like features of pay such as Account and Issuer.
 * Accounts have been replaced by Identity from neuclear-id
 * Issuer is now Asset which is a subclass of Identity
 * AssetController supports more than one Asset. Which is important for most non ecurrency implementations.
 * TransferRequest/Receipt and its Held companions are now SignedNamedObjects. Thus to create them you must use
 * their matching TransferRequest/ReceiptBuilder classes.
 * PaymentProcessor has been renamed CurrencyController. I will extract a superclass later to be named AbstractLedgerController
 * which will handle all neuclear-ledger based AssetControllers.
 *
 * Revision 1.5  2003/11/06 23:48:27  pelle
 * Major Refactoring of CurrencyController.
 * Factored out AssetController to be new abstract parent class together with most of its support classes.
 * Created (Half way) AssetControlClient, which can perform transactions on external AssetControllers via NeuClear.
 * Created the first attempt at the ExchangeAgent. This will need use of the AssetControlClient.
 * SOAPTools was changed to return a stream. This is required by the VerifyingReader in NeuClear.
 *
 * Revision 1.4  2003/10/21 22:30:33  pelle
 * Renamed NeudistException to NeuClearException and moved it to org.neuclear.commons where it makes more sense.
 * Unhooked the XMLException in the xmlsig library from NeuClearException to make all of its exceptions an independent hierarchy.
 * Obviously had to perform many changes throughout the code to support these changes.
 *
 * Revision 1.3  2003/09/26 23:52:47  pelle
 * Changes mainly in receiver and related fun.
 * First real neuclear stuff in the payment package. Added TransferContract and AssetControllerReceiver.
 *
 * Revision 1.2  2003/02/11 14:47:04  pelle
 * Added benchmarking code.
 * DigestValue is now a required part.
 * If you pass a keypair when you sign, you get the PublicKey included as a KeyInfo block within the signature.
 *
 * Revision 1.1  2003/01/18 18:12:31  pelle
 * First Independent commit of the Independent XML-Signature API for NeuDist.
 *
 * Revision 1.6  2003/01/16 19:16:08  pelle
 * Major Structural Changes.
 * We've split the test classes out of the normal source tree, to enable Maven's test support to work.
 * WARNING
 * for Development purposes the code does not as of this commit until otherwise notified actually verifysigs.
 * We are reworking the XMLSig library and need to continue work elsewhere for the time being.
 * DO NOT USE THIS FOR REAL APPS
 *
 * Revision 1.5  2002/12/17 21:41:03  pelle
 * First part of refactoring of SignedNamedObject and SignedObject Interface/Class parings.
 *
 * Revision 1.4  2002/12/17 20:34:44  pelle
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
 * Revision 1.3  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 */
package org.neuclear.xml.soap;

/**
 * @author pelleb
 * @version $Revision: 1.4 $
 */

import org.dom4j.*;
import org.dom4j.io.SAXReader;
import org.neuclear.commons.NeuClearException;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public final class SOAPTools {


    public static Element soapRequestElement(final String endpoint, final Element request, final String soapAction) throws NeuClearException {
        try {
            return soapRequestElement(new URL(endpoint), request, soapAction);
        } catch (MalformedURLException e) {
            throw new NeuClearException(e);
        }
    }

    public static InputStream soapRequest(final String endpoint, final String request, final String soapAction) throws NeuClearException {
        try {
            return soapRequest(new URL(endpoint), request, soapAction);
        } catch (MalformedURLException e) {
            throw new NeuClearException(e);
        }
    }

    public static Element soapRequestElement(final URL endpoint, final Element request, final String soapAction) throws NeuClearException {
        try {
            return soapRequestElement(endpoint.openConnection(), request, soapAction);
        } catch (IOException e) {
            throw new NeuClearException(e);
        }

    }

    public static InputStream soapRequest(final URL endpoint, final String request, final String soapAction) throws NeuClearException {
        try {
            return soapRequest(endpoint.openConnection(), request, soapAction);
        } catch (IOException e) {
            throw new NeuClearException(e);
        }
    }

    public static InputStream soapRequest(final URLConnection conn, final Element request, final String soapAction) throws NeuClearException {
        return soapRequest(conn, request.asXML(), soapAction);
    }

    public static InputStream soapRequest(final URLConnection conn, final String request, final String soapAction) throws NeuClearException {
        try {
            //Set Headers
            conn.setDoOutput(true);
            conn.setDoInput(true);
            if (conn instanceof HttpURLConnection) {
                ((HttpURLConnection) conn).setRequestMethod("POST");
                ((HttpURLConnection) conn).setRequestProperty("Content-type", "text/xml");
                ((HttpURLConnection) conn).setRequestProperty("SOAPAction", soapAction);
            }
            final OutputStream out = conn.getOutputStream();
            out.write(SOAP_START);
            out.write(request.getBytes());
            out.write(SOAP_END);
            out.close();
            return conn.getInputStream();
        } catch (IOException e) {
            throw new NeuClearException(e);
        }
    }

    public static Element soapRequestElement(final URLConnection conn, final Element request, final String soapAction) throws NeuClearException, IOException {
        try {
            final BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                            soapRequest(conn, request, soapAction)
                    ));
            final SAXReader reader = new SAXReader();
            final Document document = reader.read(in);
            in.close();
            final Element envelope = document.getRootElement();
            if (envelope.getName().equals("Envelope")) {
                final Element body = (Element) envelope.elements().get(0);
                if (body != null) {
                    return (Element) body.elements().get(0);
                }

            }
            return null;
        } catch (DocumentException e) {
            throw new NeuClearException(e);
        }
    }

    static QName createEnvelopeQName() {
        return DocumentHelper.createQName("Body", DocumentHelper.createNamespace("SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/"));
    }

    static final byte SOAP_START[] = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Body>\n".getBytes();
    static final byte SOAP_END[] = "</SOAP-ENV:Body></SOAP-ENV:Envelope>".getBytes();
}
