package org.neuclear.xml.xmlsec;

import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.neuclear.commons.Utility;
import org.neuclear.commons.crypto.passphraseagents.UserCancellationException;
import org.neuclear.commons.crypto.signers.NonExistingSignerException;
import org.neuclear.commons.crypto.signers.Signer;
import org.neuclear.xml.XMLTools;

import java.security.KeyPair;
import java.util.List;

/**
 * This is a standard Enveloping Signature with only one data object object.
 */
public class DataObjectSignature extends XMLSignature {

    /**
     * Verifies an Enveloping Signature with a Data Object.
     *
     * @param elem
     * @throws XMLSecurityException
     * @throws InvalidSignatureException
     */
    public DataObjectSignature(Element elem) throws XMLSecurityException, InvalidSignatureException {
        super(elem);
    }

    /**
     * Creates a new Enveloping Signature containing one data object. Uses the given Signer and alias to
     * sign it.
     *
     * @param alias
     * @param signer
     * @param elem   Element to embed in Data Object
     * @throws XMLSecurityException
     * @throws UserCancellationException
     * @throws NonExistingSignerException
     * @see Signer
     */
    public DataObjectSignature(String alias, Signer signer, Element elem) throws XMLSecurityException, UserCancellationException, NonExistingSignerException {
        super(alias, signer);
        si.addEnvelopingReference(addDataObject("data", elem));
        sign(alias, signer);
    }

    /**
     * Creates a new Enveloping Signature containing one data object. Signs it using the given KeyPair
     *
     * @param kp
     * @param elem Element to embed in Data Object
     * @throws XMLSecurityException
     */
    public DataObjectSignature(KeyPair kp, Element elem) throws XMLSecurityException {
        super(kp.getPublic());
        si.addEnvelopingReference(addDataObject("data", elem));
        sign(kp);
    }

    protected void verifyReferencesStructure() throws InvalidReferencesException {
        List refs = si.getReferences();
        if (refs.size() != 1)
            throw new InvalidReferencesException(refs.size());
        final String uri = si.getPrimaryReference().getUri();
        if (Utility.isEmpty(uri))
            throw new InvalidReferencesException("Empty URI");
        if (!uri.startsWith("#"))
            throw new InvalidReferencesException("URI does not start with '#'");
        final String id = uri.substring(1);
        Element object = XMLTools.getByID(getElement(), id);
        if (object == null)
            throw new InvalidReferencesException("Object with id: " + id + " is null");
        if (!object.getName().equals("Object"))
            throw new InvalidReferencesException("Referenced object is not an Object element, but a: " + object.getName());
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
