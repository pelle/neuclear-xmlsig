/*
 * $Id: XMLTools.java,v 1.11 2004/09/07 18:48:03 pelle Exp $
 * $Log: XMLTools.java,v $
 * Revision 1.11  2004/09/07 18:48:03  pelle
 * Added support for dom4j 1.5 and added a new XPP3Reader
 *
 * Revision 1.10  2004/06/08 05:57:52  pelle
 * Many changes throughout. In particular with regards to character encoding etc.
 * The SigningServer now notifies the user and quits if another application is using the same port.
 * ServletSignerFactory, now accepts a passphrase in web.xml
 *
 * Revision 1.9  2004/04/28 17:36:57  pelle
 * Updated documentation for 0.13
 * This will be release 0.13
 *
 * Revision 1.8  2004/04/26 23:57:48  pelle
 * Trying to find the verifying error
 *
 * Revision 1.7  2004/04/18 01:03:48  pelle
 * Added another varient of the id attribute to the getElementById method.
 *
 * Revision 1.6  2004/01/14 16:34:27  pelle
 * New model of references and signatures now pretty much works.
 * I am still not 100% sure on the created enveloping signatures. I need to do more testing.
 *
 * Revision 1.5  2004/01/13 23:37:59  pelle
 * Refactoring parts of the core of XMLSignature. There shouldnt be any real API changes.
 *
 * Revision 1.4  2003/12/10 23:57:05  pelle
 * Did some cleaning up in the builders
 * Fixed some stuff in IdentityCreator
 * New maven goal to create executable jarapp
 * We are close to 0.8 final of ID, 0.11 final of XMLSIG and 0.5 of commons.
 * Will release shortly.
 *
 * Revision 1.3  2003/11/21 04:44:31  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.2  2003/11/19 23:33:17  pelle
 * Signers now can generatekeys via the generateKey() method.
 * Refactored the relationship between SignedNamedObject and NamedObjectBuilder a bit.
 * SignedNamedObject now contains the full xml which is returned with getEncoded()
 * This means that it is now possible to further receive on or process a SignedNamedObject, leaving
 * NamedObjectBuilder for its original purposes of purely generating new Contracts.
 * NamedObjectBuilder.sign() now returns a SignedNamedObject which is the prefered way of processing it.
 * Updated all major interfaces that used the old model to use the new model.
 *
 * Revision 1.1.1.1  2003/11/11 16:33:20  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.7  2003/11/09 03:27:09  pelle
 * More house keeping and shuffling about mainly pay
 *
 * Revision 1.6  2003/10/21 22:30:33  pelle
 * Renamed NeudistException to NeuClearException and moved it to org.neuclear.commons where it makes more sense.
 * Unhooked the XMLException in the xmlsig library from NeuClearException to make all of its exceptions an independent hierarchy.
 * Obviously had to perform many changes throughout the code to support these changes.
 *
 * Revision 1.5  2003/09/26 23:52:47  pelle
 * Changes mainly in receiver and related fun.
 * First real neuclear stuff in the payment package. Added TransferContract and AssetControllerReceiver.
 *
 * Revision 1.4  2003/02/14 21:13:59  pelle
 * The AbstractElementProxy has a new final method .asXML()
 * which is similar to DOM4J's but it outputs the xml in the compact format and not the pretty format, thus not causing problems with Canonicalization.
 * You can now also easily get the digest of a SignedElement with the new .getEncoded() value.
 *
 * Revision 1.3  2003/02/11 14:47:03  pelle
 * Added benchmarking code.
 * DigestValue is now a required part.
 * If you pass a keypair when you sign, you get the PublicKey included as a KeyInfo block within the signature.
 *
 * Revision 1.2  2003/02/08 20:55:07  pelle
 * Some documentation changes.
 * Major reorganization of code. The code is slowly being cleaned up in such a way that we can
 * get rid of the org.neuclear.utils package and split out the org.neuclear.xml.soap package.
 * Got rid of tons of unnecessary dependencies.
 *
 * Revision 1.1  2003/01/18 18:12:31  pelle
 * First Independent commit of the Independent XML-Signature API for NeuDist.
 *
 * Revision 1.5  2003/01/16 22:20:03  pelle
 * First Draft of new generalised Ledger Interface.
 * Currently we have a Book and Transaction class.
 * We also need a Ledger class and a Ledger Factory.
 *
 * Revision 1.4  2002/09/29 00:22:10  pelle
 * Several cosmetic changes.
 * First attempt at a new CommandLine tool for signing and creating namespace files.
 * This will be used by people to create requests for namespaces.
 *
 * Revision 1.3  2002/09/21 23:11:16  pelle
 * A bunch of clean ups. Got rid of as many hard coded URL's as I could.
 *
 * Revision 1.2  2002/09/21 16:45:53  pelle
 * Got the simple web based signing service working.
 * There is also a simple User Authentication Web app to demonstrate.
 * Docs to follow.
 *
 * Revision 1.1.1.1  2002/09/18 10:55:55  pelle
 * First release in new CVS structure.
 * Also first public release.
 * This implemnts simple named objects.
 * - Identity Objects
 * - NSAuth Objects
 *
 * Storage systems
 * - In Memory Storage
 * - Clear text file based storage
 * - Encrypted File Storage (with SHA256 digested filenames)
 * - CachedStorage
 * - SoapStorage
 *
 * Simple SOAP client/server
 * - Simple Single method call SOAP client, for arbitrary dom4j based requests
 * - Simple Abstract SOAP Servlet for implementing http based SOAP Servers
 *
 * Simple XML-Signature Implementation
 * - Based on dom4j
 * - SHA-RSA only
 * - Very simple (likely imperfect) highspeed canonicalizer
 * - Zero support for X509 (We dont like that anyway)
 * - Super Simple
 *
 *
 * Revision 1.4  2002/06/17 20:48:33  pelle
 * The NS functionality should now work. FileStore is working properly.
 * The example .ns objects in the neuspace folder have been updated with the
 * latest version of the format.
 * "neuspace/root.ns" should now be considered the universal parent of the
 * neuclear system.
 * Still more to go, but we're getting there. I will now focus on a quick
 * Web interface. After which Contracts will be added.
 *
 * Revision 1.3  2002/06/13 19:04:08  pelle
 * A start to a web interface into the architecture.
 * We're getting a bit further now with functionality.
 *
 * Revision 1.2  2002/06/05 23:42:05  pelle
 * The Throw clauses of several method definitions were getting out of hand, so I have
 * added a new wrapper exception NeuClearException, to keep things clean in the ledger.
 * This is used as a catchall wrapper for all Exceptions in the underlying API's such as IOExceptions,
 * XML Exceptions etc.
 * You can catch any Exception and rethrow it using Utility.rethrowException(e) as a quick way of handling
 * exceptions.
 * Otherwise the Store framework and the NameSpaces are really comming along quite well. I added a CachedStore
 * which wraps around any other Store and caches the access to the store.
 *
 * Revision 1.1.1.1  2002/05/29 10:02:23  pelle
 * Lets try one more time. This is the first rev of the next gen of Neudist
 *
 *
 */
package org.neuclear.xml;

/**
 * @author pelleb
 * @version $Revision: 1.11 $
 */

import org.dom4j.*;
import org.dom4j.dom.DOMDocument;
import org.dom4j.io.*;
import org.xmlpull.v1.XmlPullParserException;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;


public final class XMLTools {
    /**
     * public static void writeDom(Document doc,OutputStream out) throws IOException{
     * try {
     * <p/>
     * TransformerFactory fact=TransformerFactory.newInstance();
     * Transformer tran=fact.newTransformer();
     * tran.setOutputProperty(OutputKeys.INDENT,"2");
     * tran.transform(new DOMSource(doc),new StreamResult(out));
     * } catch (TransformerFactoryConfigurationError error) {
     * Utility.handleException(error);
     * } catch (TransformerException e) {
     * Utility.handleException(e);
     * }
     * //            SerializerToXML serializer = new SerializerToXML();
     * //            // Insert your PipedOutputStream here instead of System.out!
     * //            serializer.indent(2);
     * //
     * //            serializer.setOutputStream(out);
     * //            serializer.serialize(doc);
     * }
     */
    public static boolean isAttributeTrue(final Element elem, final String name) {
        return isTrue(elem.attributeValue(name), false);
    }

    public static Document newDocument() {
        return DocumentHelper.createDocument();
    }

    public static Document loadDocument(final String url) throws XMLException {
        try {
            return loadDocument(new URL(url));
        } catch (MalformedURLException e) {
            throw new XMLException(e);
        }
    }

    public static Document loadDocument(final URL url) throws XMLException {
        try {
            final XPP3Reader xmlReader = new XPP3Reader();
            return xmlReader.read(url);
        } catch (Exception e) {
            throw new XMLException(e);
        }
    }

    public static Document loadDocument(final InputStream is) throws XMLException {
        try {
            final XPP3Reader xmlReader = new XPP3Reader();
            return xmlReader.read(is);
        } catch (Exception e) {
            throw new XMLException(e);
        }
    }

    public static Document loadDocument(final File f) throws XMLException {
        final XPP3Reader xmlReader = new XPP3Reader();
        try {

            return xmlReader.read(f);
        } catch (DocumentException e) {
            throw new XMLException(e);
        } catch (IOException e) {
            throw new XMLException(e);
        } catch (XmlPullParserException e) {
            throw new XMLException(e);
        }
    }

    public static void writeFile(final File outputFile, final Document doc) throws XMLException {
        writeFile(outputFile, doc.getRootElement());
    }

    public static void writeFile(final File outputFile, final Element doc) throws XMLException {
        try {
            writeFile(new FileOutputStream(outputFile), doc);
        } catch (FileNotFoundException e) {
            rethrowException(e);
        }
    }

    public static void writeFile(final OutputStream out, final Element doc) throws XMLException {

        try {
//            final Canonicalizer canon = new Canonicalizer();
//            byte[] data = canon.canonicalize(doc);
//            out.write(data);
//            out.close();
            final XMLWriter writer = new XMLWriter(out, getOutputFormat());
            writer.write(doc);
            writer.close();
        } catch (IOException e) {
            rethrowException(e);
        }
    }

    public static String asXML(final Element doc) throws XMLException {
        final StringWriter ow = new StringWriter();
        try {
            final XMLWriter writer = new XMLWriter(ow, getOutputFormat());
            writer.write(doc);
            writer.close();
        } catch (IOException e) {
            rethrowException(e);
        }
        return ow.toString();
    }

    private static OutputFormat getOutputFormat() {
        final OutputFormat format = OutputFormat.createCompactFormat();
        format.setEncoding("UTF-8");
        format.setExpandEmptyElements(false);
        format.setIndent(false);
        format.setNewlines(false);
        format.setPadText(false);
        format.setTrimText(false);
        return format;
    }

    public final org.w3c.dom.Document doc2dom(final Document doc) throws XMLException {
        if (!(doc instanceof DOMDocument)) {
            try {
                final DOMWriter domWriter = new DOMWriter();
                return domWriter.write(doc);
            } catch (DocumentException e) {
                rethrowException(e);
            }
        }
        return (org.w3c.dom.Document) doc;
    }

    public final Document dom2doc(final org.w3c.dom.Document dom) {
        if (dom instanceof DOMDocument)
            return (DOMDocument) dom;
        else {
            final DOMReader domReader = new DOMReader();
            return domReader.read(dom);
        }
    }

    public static boolean isTrue(String clause, final boolean defaultVal) {
        if (isEmpty(clause))
            return defaultVal;
        clause = clause.toLowerCase();
        return (clause.equals("yes") || clause.equals("y") || clause.equals("1") || clause.equals("true"));
    }

    public static boolean isEmpty(final Object obj) {
        return (obj == null || obj.toString().equals(""));
    }

    public static void rethrowException(final Throwable e) throws XMLException {
        throw new XMLException(e);
    }

    /**
     * This is used to find an Elemente with a given ID.
     * This is necessary because of Dom4j's use of the ID attribute
     * and not the more common in XMLSignature Id attribute.
     *
     * @param elem
     * @param id
     * @return
     */
    public static Element getByID(Element elem, String id) {
        return getByID(elem.getDocument(), id);
    }

    /**
     * This is used to find an Elemente with a given ID.
     * This is necessary because of Dom4j's use of the ID attribute
     * and not the more common in XMLSignature Id attribute.
     *
     * @param doc
     * @param id
     * @return
     */
    public static Element getByID(Document doc, String id) {
        Element object = doc.elementByID(id);
        if (object != null)
            return object;
        XPath xp = DocumentHelper.createXPath("//*[@Id='" + id + "']");
        object = (Element) xp.selectSingleNode(doc);
        if (object != null)
            return object;
        xp = DocumentHelper.createXPath("//*[@id='" + id + "']");
        object = (Element) xp.selectSingleNode(doc);
        return object;
    }

}
