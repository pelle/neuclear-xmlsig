package org.neuclear.xml.xmlsec;

import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.Signer;

import java.security.KeyPair;
import java.util.List;

/**
 * This is a standard Enveloped Signature with only one Reference object.
 */
public class DataObjectSignature extends XMLSignature {
    public DataObjectSignature(Element elem) throws XMLSecurityException, InvalidSignatureException {
        super(elem);
    }

    public DataObjectSignature(String name, Signer signer, Element elem) throws XMLSecurityException, UserCancellationException, NonExistingSignerException {
        super(name, signer);
        si.addEnvelopingReference(addDataObject("data", elem));
        sign(name, signer);
    }

    public DataObjectSignature(KeyPair kp, Element elem) throws XMLSecurityException {
        super(kp.getPublic());
        si.addEnvelopingReference(addDataObject("data", elem));
        sign(kp);
    }

    protected void verifyReferencesStructure() throws InvalidReferencesException {
        List refs = si.getReferences();
        if (refs.size() != 1)
            throw new InvalidReferencesException(refs.size());
        if (Utility.isEmpty(si.getPrimaryReference().getUri()))
            throw new InvalidReferencesException();

    }

    private Element addDataObject(final String id, final Element root) {
        final Element objElem = XMLSecTools.createElementInSignatureSpace("Object");
        objElem.addAttribute("Id", id);
        DocumentHelper.createDocument(getElement());//As Signature Element is parent we will now add a doc
        objElem.add(root);
        getElement().add(objElem);
        return objElem;
    }

}
