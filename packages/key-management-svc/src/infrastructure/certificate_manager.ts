"use strict";

import forge, {pki} from "node-forge";
import fs from "fs";
import {ILogger} from "@mojaloop/logging-bc-public-types-lib";

import {CertificatesHelper} from "@mojaloop/security-bc-client-lib";

export class CertificateManager {
    private _caPubKeyPem: string;
    private _caPrivateKeyPem: string;
    private _caPubCert: forge.pki.Certificate;
    private _caPrivateKey: forge.pki.PrivateKey;
    private _logger: ILogger;
    private _ca_store: pki.CAStore = pki.createCaStore();

    constructor(caPrivateKeyPath: string, caPublicKeyPath: string, logger: ILogger) {
        this._logger = logger;

        this._caPubKeyPem = fs.readFileSync(caPublicKeyPath, "utf8");
        this._caPrivateKeyPem = fs.readFileSync(caPrivateKeyPath, "utf8");
        this._caPubCert = forge.pki.certificateFromPem(this._caPubKeyPem);
        this._caPrivateKey = forge.pki.privateKeyFromPem(this._caPrivateKeyPem);

        this._ca_store.addCertificate(pki.certificateFromPem(this._caPubKeyPem));
    }

    signCSR(csrPem: string): string {
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

        return forge.pki.certificateToPem(newParticipantCert);
    }

    getHubCAPubCert(): string {
        return this._caPubKeyPem;
    }

    verifyCert(certPem: string): boolean {
        const cert = pki.certificateFromPem(certPem);
        return pki.verifyCertificateChain(this._ca_store, [cert]);
    }

    static generateCAKeyPair(caPrivateKeyPath: string, caPublicKeyPath: string): string {
        const certHelper = new CertificatesHelper();
        // Generate a keypair
        const keys = forge.pki.rsa.generateKeyPair(2048);
        const signingKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
        const certPem = certHelper.createX590CertificateAuthorityCert(

            signingKeyPem,
            // commonName, country, state, locality, orgName, orgUnit,
            "vNextHub CA", "US", "Virginia", "Blacksburg", "Mojaloop", "vNextHub CA",
            10);

        fs.writeFileSync(caPrivateKeyPath, signingKeyPem, "utf8");
        fs.writeFileSync(caPublicKeyPath, certPem, "utf8");
        return certPem;
    }
}
