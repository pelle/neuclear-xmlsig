package org.neuclear.xml.c14;

/**
 * (C) 2003 Antilles Software Ventures SA
 * User: pelleb
 * Date: Feb 3, 2003
 * Time: 5:56:42 AM
 * $Id: Canonicalizer.java,v 1.8 2004/02/19 15:30:08 pelle Exp $
 * $Log: Canonicalizer.java,v $
 * Revision 1.8  2004/02/19 15:30:08  pelle
 * Various cleanups and corrections
 *
 * Revision 1.7  2004/02/19 00:27:59  pelle
 * Discovered several incompatabilities with the xmlsig implementation. Have been working on getting it working.
 * Currently there is still a problem with enveloping signatures and it seems enveloped signatures done via signers.
 *
 * Revision 1.6  2004/01/14 16:34:27  pelle
 * New model of references and signatures now pretty much works.
 * I am still not 100% sure on the created enveloping signatures. I need to do more testing.
 *
 * Revision 1.5  2004/01/14 06:42:37  pelle
 * Got rid of the verifyXXX() methods
 *
 * Revision 1.4  2003/12/10 23:57:04  pelle
 * Did some cleaning up in the builders
 * Fixed some stuff in IdentityCreator
 * New maven goal to create executable jarapp
 * We are close to 0.8 final of ID, 0.11 final of XMLSIG and 0.5 of commons.
 * Will release shortly.
 *
 * Revision 1.3  2003/11/21 04:44:30  pelle
 * EncryptedFileStore now works. It uses the PBECipher with DES3 afair.
 * Otherwise You will Finaliate.
 * Anything that can be final has been made final throughout everyting. We've used IDEA's Inspector tool to find all instance of variables that could be final.
 * This should hopefully make everything more stable (and secure).
 *
 * Revision 1.2  2003/11/11 21:18:07  pelle
 * Further vital reshuffling.
 * org.neudist.crypto.* and org.neudist.utils.* have been moved to respective areas under org.neuclear.commons
 * org.neuclear.signers.* as well as org.neuclear.passphraseagents have been moved under org.neuclear.commons.crypto as well.
 * Did a bit of work on the Canonicalizer and changed a few other minor bits.
 *
 * Revision 1.1.1.1  2003/11/11 16:33:22  pelle
 * Moved over from neudist.org
 * Moved remaining common utilities into commons
 *
 * Revision 1.12  2003/10/29 21:15:53  pelle
 * Refactored the whole signing process. Now we have an interface called Signer which is the old SignerStore.
 * To use it you pass a byte array and an alias. The sign method then returns the signature.
 * If a Signer needs a passphrase it uses a PassPhraseAgent to present a dialogue box, read it from a command line etc.
 * This new Signer pattern allows us to use secure signing hardware such as N-Cipher in the future for server applications as well
 * as SmartCards for end user applications.
 *
 * Revision 1.11  2003/09/29 23:44:54  pelle
 * Trying to tweak Canonicalizer to function better.
 * Apparently the built in Sun JCE doesnt like the Keysizes of NSROOT
 * So now CryptoTools forces the use of BouncyCastle
 *
 * Revision 1.10  2003/02/24 13:32:23  pelle
 * Final doc changes for 0.8
 *
 * Revision 1.9  2003/02/24 00:40:57  pelle
 * Cleaned up a lot of code for new fixed processing model.
 * It all still work as before, but will be easier to modify the Reference processing model which is the only
 * main thing todo besides X509 and HMAC-SHA1 support.
 *
 * Revision 1.8  2003/02/22 16:54:29  pelle
 * Major structural changes in the whole processing framework.
 * Verification now supports Enveloping and detached signatures.
 * The reference element is a lot more important at the moment and handles much of the logic.
 * Replaced homegrown Base64 with Blackdowns.
 * Still experiencing problems with decoding foreign signatures. I reall dont understand it. I'm going to have
 * to reread the specs a lot more and study other implementations sourcecode.
 *
 * Revision 1.7  2003/02/18 00:03:32  pelle
 * Moved the Signer classes from neuclearframework into neuclear-xmlsig
 *
 * Revision 1.6  2003/02/11 14:47:03  pelle
 * Added benchmarking code.
 * DigestValue is now a required part.
 * If you pass a keypair when you sign, you get the PublicKey included as a KeyInfo block within the signature.
 *
 * Revision 1.5  2003/02/08 20:55:07  pelle
 * Some documentation changes.
 * Major reorganization of code. The code is slowly being cleaned up in such a way that we can
 * get rid of the org.neuclear.utils package and split out the org.neuclear.xml.soap package.
 * Got rid of tons of unnecessary dependencies.
 *
 * Revision 1.4  2003/02/08 18:48:07  pelle
 * The Signature phase has been rewritten.
 * There now is a new Class called QuickEmbeddedSignature which is more in line with my original idea for this library.
 * It simply has a template of the xml and signs it in a standard way.
 * The original XMLSignature class is still used for verification and will in the future handle more thoroughly
 * all the various flavours of XMLSig.
 * XMLSecTools has got different flavours of canonicalize now. Including one where you can pass it a Canonicaliser to use.
 * Of the new Canonicalizer's are CanonicalizerWithComments, which I accidently left out of the last commit.
 * And CanonicalizerWithoutSignature which leaves out the Signature in the Canonicalization phase and is thus
 * a lot more efficient than the previous approach.
 *
 * Revision 1.3  2003/02/08 17:06:45  pelle
 * Added support for Canonicalized XML Subsets.
 * Only problem is it doesnt work. This should hopefully be fixed soon.
 * There is a test case which has been temporarily disabled.
 * Message has been sent to dom4j mailing list. I'm not sure if it's something I've done wrong or if it's a bug
 * in Jaxen (the XPath implementation used by Dom4j)
 * I've also added Canonicalizer with comments.
 *
 * Revision 1.2  2003/02/07 22:33:11  pelle
 * Compliance mostly working.
 * Merlin's Example 7 hasn't been implemented, but mainly because we havent written the test case yet.
 * A few of the example c14n files had trailing new lines. I'm not sure what the spec says about that, but I
 * got rid of them as my implementation doesnt support those. Who is right?
 * Example 4 has problems with the final element. This seems to be causing problems for lots of people.
 * To workaround it, I've removed the offending lines from all the files.
 * TBH I dont understand whats going on with it. Will put it on the back burner and come back.
 *
 * Revision 1.1  2003/02/07 21:14:45  pelle
 * Much improved Canonicalizer and Test Suite.
 * I've added the merlin-xmldsig-eight Canonicalization test suite.
 * All tests still dont work.
 *
 */

import org.dom4j.tree.NamespaceStack;
import org.neuclear.xml.ElementProxy;
import org.neuclear.xml.XMLTools;
import org.neuclear.xml.transforms.TransformerFactory;
import org.neuclear.xml.transforms.XPathTransform;
import org.neuclear.xml.xmlsec.XMLSecurityException;

import java.io.*;
import java.nio.charset.Charset;
import java.util.*;

/**
 * XML Canonicalizer.
 * This "mostly" supports the <a href="http://www.w3c.org">W3C</a>
 * <a href="http://www.w3.org/TR/2000/WD-xml-c14n-20001011">Canonical XML</a> standard.
 * <p/>
 * Usage:<br>
 * <pre>Canonicalizer canon=new Canonicalizer(writer);//writer is a preinitialized instance of a java.io.Writer
 * canon.canonicalize(doc); // Canonicalizes the document or element and outputs it to the writer
 * </pre>
 */
public class Canonicalizer extends XPathTransform {

    public Canonicalizer() {
        this(XPATH_WO_COMMENTS);
    }

    protected Canonicalizer(final String xpath) {
        super(xpath);

    }

    private void init() {
        try {
            bos = new ByteArrayOutputStream();
            writer = new BufferedWriter(new OutputStreamWriter(bos, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            System.out.println("Strange... we do not have UTF-8");
            throw new RuntimeException(e.getLocalizedMessage());
        }
        notfirst = false;
        namespaceStack = new NamespaceStack();

    }


    /**
     * Canonicalizes a node and outputs it to the writer
     * 
     * @param node 
     */
    public final byte[] canonicalize(final Object node) throws XMLSecurityException {
        try {
            init();
            write(node);
            return getBytes();
        } catch (IOException e) {
            throw new XMLSecurityException(e);
        }
    }

    /**
     * Creates a subset of a node based on it's xpath and outputs it to the writer
     * Note, for this to return wellformed xml the xpath most be formatted to produce it.
     * 
     * @param node  node
     * @param xpath subset expression
     * @throws IOException 
     */
    public final byte[] canonicalizeSubset(final Node node, final String xpath) throws IOException {
        init();
        final XPath xpathSelector = DocumentHelper.createXPath(xpath);
        final Map nsmap = new HashMap();
        nsmap.put("ietf", "http://www.ietf.org");
        xpathSelector.setNamespaceURIs(nsmap);
        final List nl = xpathSelector.selectNodes(node);
        write(nl);
        return getBytes();
    }

    private byte[] getBytes() throws IOException {
        writer.close();
        bos.close();
        return bos.toByteArray();
    }

    private void write(final Object obj) throws IOException {
        if (obj instanceof Node)
            writeNode((Node) obj);
        else if (obj instanceof ElementProxy) {
            writeNode(((ElementProxy) obj).getElement());
        } else if (obj instanceof List) {
            final Iterator iter = ((List) obj).iterator();
            while (iter.hasNext()) {
                final Node node = (Node) iter.next();
                write(node);
            }
        } else {
            writer.write(obj.toString());
        }
    }

    private void writeNode(final Node node) throws IOException {
        if (!matches(node))
            return;

        final int nodeType = node.getNodeType();

        switch (nodeType) {
            case Node.ELEMENT_NODE:
                writeElement((Element) node);
                break;
            case Node.ATTRIBUTE_NODE:
                writeAttribute((Attribute) node);
                break;
            case Node.TEXT_NODE:
            case Node.CDATA_SECTION_NODE:
                writeEscapedString(node.getText());
                break;
            case Node.ENTITY_REFERENCE_NODE:
                writeEntity((Entity) node);
                break;
            case Node.PROCESSING_INSTRUCTION_NODE:
                writeProcessingInstruction((ProcessingInstruction) node);
                break;
            case Node.COMMENT_NODE:
                writeComment((Comment) node);
                break;
            case Node.DOCUMENT_NODE:
                writeDocument((Document) node);
                break;
            case Node.DOCUMENT_TYPE_NODE:
                writeDocType((DocumentType) node);
                break;
            case Node.NAMESPACE_NODE:
                // Will be output with attributes
                //write((Namespace) node);
                break;
            default:
                throw new IOException("Invalid node type: " + node);

        }

        notfirst = true;
    }

    private void outputLF(final Node node) throws IOException {
        if (node.getParent() == null && notfirst) {
            writer.write(LF);
        }
    }

    private void writeDocType(final DocumentType documentType) {
    }

    private void writeDocument(final Document document) throws IOException {
        for (int i = 0, size = document.nodeCount(); i < size; i++) {
            final Node node = document.node(i);
            write(node);
        }
    }

    private void writeComment(final Comment comment) throws IOException {
        outputLF(comment);
        writer.write("<!--");
        writer.write(comment.getText());
        writer.write("-->");
    }

    private void writeProcessingInstruction(final ProcessingInstruction processingInstruction) throws IOException {
        outputLF(processingInstruction);
        writer.write("<?");
        writer.write(processingInstruction.getName());
        if (!XMLTools.isEmpty(processingInstruction.getText())) {
            writer.write(" ");
            writer.write(processingInstruction.getText());
        }
        writer.write("?>");
    }

    private void writeEntity(final Entity entity) throws IOException {
        final String text = entity.getText();
        final int hashLoc = text.indexOf('#');
        writer.write(entity.getText());    //TODO entities need to be expanded
    }

    private void writeAttribute(final Attribute attribute) throws IOException {
        writer.write(" ");
        writer.write(attribute.getQualifiedName());
        writer.write("=\"");
        writeEscapedAttributeString(attribute.getValue());
//        System.out.println(attribute.getQualifiedName()+"="+attribute.getValue());
        writer.write("\"");

    }

    private void writeElement(final Element element) throws IOException {
        outputLF(element);

        final String qualifiedName = element.getQualifiedName();
        writer.write("<");
        writer.write(qualifiedName);

        final int previouslyDeclaredNamespaces = namespaceStack.size();
        final Namespace ns = element.getNamespace();
        final TreeMap sorted = new TreeMap();
        if (isNamespaceDeclaration(ns)) {
            namespaceStack.push(ns);
            writeNamespace(ns, sorted);
        } else if (ns.getURI() != null &&
                ns.getURI().equals("") &&
                element.getParent() != null &&
                element.getParent().getNamespaceURI() != null
                && !element.getParent().getNamespaceURI().equals("")
        ) {
            writeNamespace(ns, sorted);
        }

        final Iterator nsiter = element.additionalNamespaces().iterator();
        while (nsiter.hasNext()) {
            final Namespace namespace = (Namespace) nsiter.next();
            if (!namespaceStack.contains(namespace)) {
                writeNamespace(namespace, sorted);
                namespaceStack.push(namespace);
            }
        }
        writeAttributes(element, sorted);

        writer.write(">");
        for (int i = 0, size = element.nodeCount(); i < size; i++) {
            final Node node = element.node(i);
            write(node);
        }
        writer.write("</");
        writer.write(qualifiedName);
        writer.write(">");

        // remove declared namespaceStack from stack
        while (namespaceStack.size() > previouslyDeclaredNamespaces) {
            namespaceStack.pop();
        }

//        if (element.getSignatory()==null)
//           writer.write(LF);
    }

    private void writeNamespace(final Namespace namespace, final TreeMap sorted) throws IOException {
        if (namespace != null) {
            sorted.put("0" + namespace.getPrefix(), namespace);
        }
    }

    private void writeAttributes(final Element element, final TreeMap sorted) throws IOException {

        // I do not yet handle the case where the same prefix maps to
        // two different URIs. For attributes on the same element
        // this is illegal; but as yet we don't throw an exception
        // if someone tries to do this
        //List attr=element.attributes();


        for (int i = 0, size = element.attributeCount(); i < size; i++) {
            final Attribute attribute = element.attribute(i);
            sorted.put(attribute.getNamespaceURI() + ":" + attribute.getName(), attribute);
            final Namespace ns = attribute.getNamespace();
            if (ns != null && ns != Namespace.NO_NAMESPACE && ns != Namespace.XML_NAMESPACE) {
                final String prefix = ns.getPrefix();
                final String uri = namespaceStack.getURI(prefix);
                if (!ns.getURI().equals(uri)) { // output a new namespace declaration
                    writeNamespace(ns, sorted);
                    namespaceStack.push(ns);
                }
            }

        }
        final Iterator iter = sorted.keySet().iterator();
        while (iter.hasNext()) {
            final String name = (String) iter.next();
            final Node node = (Node) sorted.get(name);
            if (node instanceof Attribute)
                writeAttribute((Attribute) node);
            else if (node instanceof Namespace) {
                writeNSAttribute((Namespace) node);

            }
        }
    }

    private void writeNSAttribute(final Namespace namespace) throws IOException {
        final String prefix = namespace.getPrefix();
        writer.write(" xmlns");
        if (prefix != null && prefix.length() > 0) {
            writer.write(":");
            writer.write(prefix);
        }
        writer.write("=\"");
        writer.write(namespace.getURI());
        writer.write("\"");
    }

    private boolean isNamespaceDeclaration(final Namespace ns) {
        if (ns != null && ns != Namespace.NO_NAMESPACE && ns != Namespace.XML_NAMESPACE) {
            final String uri = ns.getURI();
            if (uri != null) {//&& uri.length() > 0 ) {
                if (!namespaceStack.contains(ns)) {
                    return true;

                }
            }
        }
        return false;
    }

    /**
     * This will take the pre-defined entities in XML 1.0 and
     * convert their character representation to the appropriate
     * entity reference, suitable for XML attributes.
     */
    private void writeEscapedString(final String text) throws IOException {
        int i;
        final int size = text.length();

        for (i = 0; i < size; i++) {
            switch (text.charAt(i)) {
                case '<':
                    writer.write("&lt;");
                    break;
                case '>':
                    writer.write("&gt;");
                    break;
                case '&':
                    writer.write("&amp;");
                    break;
                case 0x0d:
                    writer.write("&#xD;");
                    break;
                default :

                    writer.write(text.charAt(i));

            }
        }
    }

    /**
     * This will take the pre-defined entities in XML 1.0 and
     * convert their character representation to the appropriate
     * entity reference, suitable for XML attributes.
     */
    private void writeEscapedAttributeString(final String text) throws IOException {
        int i;
        final int size = text.length();
        for (i = 0; i < size; i++) {
            switch (text.charAt(i)) {
                case '<':
                    writer.write("&lt;");
                    break;
//             case '>' :
//                 writer.write("&gt;");
//                 break;
                case '&':
                    writer.write("&amp;");
                    break;
                case '"':
                    writer.write("&quot;");
                    break;
                case 0x0d:
                    writer.write("&#xD;");
                    break;
                case 0x09:
                    writer.write("&#x9;");
                    break;
                case 0x0a:
                    writer.write("&#xA;");
                    break;
//                case '\'' :
//                    writer.write("&apos;");
//                    break;
                default :
                    writer.write(text.charAt(i));
            }
        }
    }

    private Writer writer;
    private ByteArrayOutputStream bos;
    private boolean notfirst = false;
    private NamespaceStack namespaceStack = new NamespaceStack();

    public static final String XPATH_WO_COMMENTS = "(//. | //@* | //namespace::*| self::processing-instruction())[not(self::comment())]";
    public static final String LF = new String(new byte[]{10});
    public final static int C14NTYPE_NORMAL = 0;
    public final static int C14NTYPE_WITH_COMMENTS = 1;
    private final static Charset UTF8 = Charset.forName("UTF-8");

    public static final String ALGORITHM = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    {
        TransformerFactory.registerTransformer(ALGORITHM, Canonicalizer.class);
    }


}