package org.neuclear.xml.transforms;

import org.dom4j.*;
import org.neuclear.xml.xmlsec.XMLSecTools;
import org.neuclear.xml.xmlsec.XMLSecurityException;

import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * User: pelleb
 * Date: Dec 21, 2002
 * Time: 3:41:12 PM
 * To change this template use Options | File Templates.
 */
public class XPathTransform extends Transform {
    public XPathTransform() {
        super(ALGORITHM);
    }

    public XPathTransform(final String xpath) {
        super(ALGORITHM);
//        this.xpath=xpath;
        setXPath(xpath);
        final Element xpElem = getElement().addElement("XPath");
        xpElem.setText(xpath);
        xpElem.addAttribute("xmlns:dsig", "&dsig;");
    }

    protected XPathTransform(final String algorithm, final String xpath) {
        super(algorithm);
//        this.xpath=xpath;
        setXPath(xpath);
    }

    private void setXPath(final String xpath) {
//        XPathFilter=DocumentHelper.createXPath(xpath);
        xpathFilter = DocumentHelper.createXPath(xpath);
        xpathFilter.setNamespaceURIs(NSMAP);

//        try {
//            xp=new Dom4jXPath(xpath);
//        } catch (JaxenException e) {
//            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
//        }
//        System.out.println("Set XPathFilter to: "+xpath);
    }

    public XPathTransform(final Element elem) throws XMLSecurityException {
        super(elem);
        final Element xpElement = elem.element("XPath");
        if (xpElement == null)
            throw new XMLSecurityException("XPath Element not found in Tranform");
        final String xpath = xpElement.getTextTrim();
        setXPath(xpath);
    }

    public final Object transformNode(final Object in) {
        if (in instanceof Element) {
            Element copy = ((Element) in).createCopy();
            return transform(copy);
        }
        return transform(in);
    }

    private final Object transform(final Object in) {
        // XPath needs a document. So if element doesnt have one we add it.
        if (in instanceof Element) {
            if (((Element) in).getDocument() == null) {
                DocumentHelper.createDocument((Element) in);
            }
        }

        if ((in instanceof Node) && !matches((Node) in)) {
            return null;
        }
        ListIterator iter = null;
        if (in instanceof List)
            iter = ((List) in).listIterator();
        else if (in instanceof Branch)
            iter = ((Branch) in).content().listIterator();
        if (iter != null) {
            while (iter.hasNext()) {
                final Node node = (Node) iter.next();
                if (transform(node) == null)
                    iter.remove();
            }
        }
        return in;
    }

    public final boolean matches(final Node node) {
        return xpathFilter.matches(node);
    }

    //   private String xpath;
    private XPath xpathFilter;
//    private BaseXPath xp;
    //private XPath xpath;

    public static final String ALGORITHM = "http://www.w3.org/TR/1999/REC-xpath-19991116";

    {
        TransformerFactory.registerTransformer(ALGORITHM, XPathTransform.class);
    }


    private static final Map NSMAP = new HashMap();

    {
        NSMAP.put("ds", XMLSecTools.XMLDSIG_NAMESPACE);
    }
}
