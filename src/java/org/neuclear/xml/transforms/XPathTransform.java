package org.neuclear.xml.transforms;

import org.dom4j.*;
import org.neuclear.xml.xmlsec.XMLSecurityException;
import org.neuclear.xml.xmlsec.XMLSecTools;

import java.util.ListIterator;
import java.util.Map;
import java.util.HashMap;
import java.util.List;

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
    public XPathTransform(String xpath) {
        super(ALGORITHM);
//        this.xpath=xpath;
        setXPath(xpath);
        Element xpElem=getElement().addElement("XPath");
        xpElem.setText(xpath);
        xpElem.addAttribute("xmlns:dsig","&dsig;");
    }

    private void setXPath(String xpath) {
//        XPathFilter=DocumentHelper.createXPath(xpath);
        xpathFilter=DocumentHelper.createXPath(xpath);
        xpathFilter.setNamespaceURIs(nsmap);

//        try {
//            xp=new Dom4jXPath(xpath);
//        } catch (JaxenException e) {
//            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
//        }
//        System.out.println("Set XPathFilter to: "+xpath);
    }

    public XPathTransform(Element elem) throws XMLSecurityException {
        super(elem);
        Element xpElement=elem.element("XPath");
        if (xpElement==null)
            throw new XMLSecurityException("XPath Element not found in Tranform");
        String xpath=xpElement.getTextTrim();
        setXPath(xpath);
    }

    public Object transformNode(Object in) {
        // XPath needs a document. So if element doesnt have one we add it.
        if (in instanceof Element){
            if (((Element)in).getDocument()==null){
                DocumentHelper.createDocument((Element)in);
            }
        }

        if ((in instanceof Node)&&!matches((Node)in)) {
                return null;
        }
        ListIterator iter=null;
        if (in instanceof List)
            iter=((List)in).listIterator();
        else if (in instanceof Branch)
            iter=((Branch)in).content().listIterator();
        if (iter!=null) {
            while (iter.hasNext()) {
                Node node = (Node) iter.next();
                if (transformNode(node)==null)
                   iter.remove();
            }
        }
        return in;
    }
    public boolean matches(Node node){
        return xpathFilter.matches(node);
    }
 //   private String xpath;
    private XPath xpathFilter;
//    private BaseXPath xp;
    //private XPath xpath;

    public static final String ALGORITHM="http://www.w3.org/TR/1999/REC-xpath-19991116";
    {
        TransformerFactory.registerTransformer(ALGORITHM,XPathTransform.class);
    }


    private static final Map nsmap=new HashMap();
    {
        nsmap.put("ds",XMLSecTools.XMLDSIG_NAMESPACE);
    }
}
