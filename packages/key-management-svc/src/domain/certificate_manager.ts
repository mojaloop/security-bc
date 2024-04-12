"use strict";

import forge, { pki } from "node-forge";

import { CertificatesHelper } from "@mojaloop/security-bc-client-lib";
import { ISecureCertificateStorage } from "./isecure_storage";

export class CertificateManager {
    private _caPubKeyPem: string;
    private _caPrivateKeyPem: string;
    private _caPubCert: forge.pki.Certificate;
    private _caPrivateKey: forge.pki.PrivateKey;
    private _ca_store: pki.CAStore = pki.createCaStore();
    private _secureStorage: ISecureCertificateStorage;

    constructor(secureStorage: ISecureCertificateStorage) {
        this._secureStorage = secureStorage;
    }

    async init() {
        this._caPubKeyPem = await this._secureStorage.getCAHubPublicKey();
        this._caPrivateKeyPem = await this._secureStorage.getCAHubPrivateKey();

        this._caPubCert = forge.pki.certificateFromPem(this._caPubKeyPem);
        this._caPrivateKey = forge.pki.privateKeyFromPem(this._caPrivateKeyPem);

        this._ca_store.addCertificate(pki.certificateFromPem(this._caPubKeyPem));
    }

    signCSR(client_id: string, csrPem: string): string {
        const participantCSR = forge.pki.certificationRequestFromPem(csrPem);

        if (participantCSR.publicKey === null) {
            throw new Error("CSR public key is null.");
        }

        if (!participantCSR.verify()) {
            throw new Error("CSR verification failed.");
        }

        const newParticipantCert = forge.pki.createCertificate();
        newParticipantCert.serialNumber = crypto.randomUUID().replace(/-/g, "");
        newParticipantCert.validity.notBefore = new Date();
        newParticipantCert.validity.notAfter = new Date();
        newParticipantCert.validity.notAfter.setFullYear(newParticipantCert.validity.notBefore.getFullYear() + 1); // 1 year validity, TODO: make this configurable

        newParticipantCert.setSubject(participantCSR.subject.attributes); // use the same subject as the CSR
        newParticipantCert.setIssuer(this._caPubCert.subject.attributes); // use the CA subject as the issuer
        newParticipantCert.publicKey = participantCSR.publicKey;
        newParticipantCert.setExtensions([
            {
                name: "basicConstraints",
                cA: false
            },
            {
                name: "keyUsage",
                keyCertSign: true,
                digitalSignature: true,
                nonRepudiation: true,
                keyEncipherment: true,
                dataEncipherment: true,
            }]);

        newParticipantCert.sign(this._caPrivateKey, forge.md.sha256.create());
        const clientCertPem = forge.pki.certificateToPem(newParticipantCert);

        this._secureStorage.storePublicCert(client_id, clientCertPem);

        return clientCertPem;
    }

    getHubCAPubCert(): string {
        return this._caPubKeyPem;
    }

    verifyCert(certPem: string): boolean {
        const cert = pki.certificateFromPem(certPem);
        return pki.verifyCertificateChain(this._ca_store, [cert]);
    }

    static generateCAKeyPairAndStore(secureStorage: ISecureCertificateStorage): string {
        const certHelper = new CertificatesHelper();
        // Generate a keypair
        const keys = forge.pki.rsa.generateKeyPair(2048);
        const signingKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
        const certPem = certHelper.createX590CertificateAuthorityCert(

            signingKeyPem,
            // commonName, country, state, locality, orgName, orgUnit,
            "vNextHub CA", "US", "Virginia", "Blacksburg", "Mojaloop", "vNextHub CA",
            10);

        secureStorage.storeCAHubPrivateKey(signingKeyPem);
        secureStorage.storeCAHubPublicKey(certPem);
        return certPem;
    }
}
