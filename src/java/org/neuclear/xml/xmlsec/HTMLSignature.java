package org.neuclear.xml.xmlsec;

import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.DOMReader;
import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.BrowsableSigner;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.Signer;
import org.w3c.tidy.Tidy;

import java.io.InputStream;
import java.security.KeyPair;
import java.util.List;

/**
 * This is a standard Enveloped Signature with only one Reference object.
 */
public class HTMLSignature extends XMLSignature {
    /**
     * Creates a standard Enveloped Signature within the given Element.
     * Uses the provided Signer and Alias to sign it.
     *
     * @param name
     * @param signer
     * @param is
     * @throws XMLSecurityException
     * @throws org.neuclear.commons.crypto.passphraseagents.UserCancellationException
     *
     * @throws org.neuclear.commons.crypto.signers.NonExistingSignerException
     *
     * @see org.neuclear.commons.crypto.signers.Signer
     */
    public HTMLSignature(String name, Signer signer, InputStream is) throws XMLSecurityException, UserCancellationException, NonExistingSignerException {
        super(name, signer);
        Tidy tidy = new Tidy();
        tidy.setXmlOut(true);
        org.w3c.dom.Document dom = tidy.parseDOM(is, System.out);
        DOMReader reader = new DOMReader();
        Document doc = reader.read(dom);
        Element html = doc.getRootElement();
        createHTMLBadge(html);
        si.getElement().addAttribute("id", "dsdigestvalue");
        si.setEnvelopedReference(html);
        html.add(getElement());
        sign(name, signer);
        sigval.addAttribute("id", "dssigvalue");
        final Element ki = getElement().element("KeyInfo");
        if (ki != null) ki.addAttribute("id", "dskeyinfo");
    }

    private void createHTMLBadge(Element elem) {
        Element head = elem.element("head");
        Element css = head.addElement("link");
        css.addAttribute("rel", "stylesheet");
        css.addAttribute("href", "http://neuclear.org/sig.css");
        css.addAttribute("type", "text/css");
        Element body = elem.element("body");
//        body.addElement("hr");
        Element title = body.addElement("p");
        title.addAttribute("id", "dsigtitle");
        title.setText("This page has been digitally signed.");
        body.addText("\n");
    }

    /**
     * Creates a standard Enveloped Signature within the given Element.
     * Uses the provided Signer and Alias to sign it.
     *
     * @param signer
     * @param is
     * @throws XMLSecurityException
     * @throws org.neuclear.commons.crypto.passphraseagents.UserCancellationException
     *
     * @see org.neuclear.commons.crypto.signers.Signer
     */
    public HTMLSignature(BrowsableSigner signer, InputStream is) throws XMLSecurityException, UserCancellationException {
        super(new SignedInfo(SignedInfo.SIG_ALG_RSA, 1));
        Tidy tidy = new Tidy();
        tidy.setXmlOut(true);
        org.w3c.dom.Document dom = tidy.parseDOM(is, null);
        DOMReader reader = new DOMReader();
        Document doc = reader.read(dom);
        Element html = doc.getRootElement();
        createHTMLBadge(html);
        si.getElement().addAttribute("id", "dsdigestvalue");
        si.setEnvelopedReference(html);
        html.add(getElement());
        sign(signer);
        sigval.addAttribute("id", "dssigvalue");
        final Element ki = getElement().element("KeyInfo");
        if (ki != null) ki.addAttribute("id", "dskeyinfo");
    }


    /**
     * Creates a standard Enveloped Signature within the given Element.
     * Uses the provided KeyPair to sign it.
     *
     * @param kp
     * @param elem
     * @throws XMLSecurityException
     */
    public HTMLSignature(KeyPair kp, Element elem) throws XMLSecurityException {
        super(kp.getPublic());
        si.setEnvelopedReference(elem);
        elem.add(getElement());
        sign(kp);
    }

    protected void verifyReferencesStructure() throws InvalidReferencesException {
        List refs = si.getReferences();
        if (refs.size() != 1)
            throw new InvalidReferencesException(refs.size());
        if (!Utility.isEmpty(si.getPrimaryReference().getUri()))
            throw new InvalidReferencesException();

    }
}
