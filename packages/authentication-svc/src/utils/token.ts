import * as crypto from "crypto";

const REFRESH_TOKEN_LENGTH = 128;

export const generateRefreshToken = () =>
  crypto.randomBytes(REFRESH_TOKEN_LENGTH / 2).toString("hex");

function convert_cert_to_SSL(cert_str:string){
    const beginCert = "-----BEGIN CERTIFICATE-----";
    const endCert = "-----END CERTIFICATE-----";

    cert_str = cert_str.replace("\n", "");
    cert_str = cert_str.replace(beginCert, "");
    cert_str = cert_str.replace(endCert, "");

    let result = beginCert;
    while(cert_str.length > 0){

        if(cert_str.length > 64){
            result += "\n" + cert_str.substring(0, 64);
            cert_str = cert_str.substring(64, cert_str.length);
        }
        else{
            result += "\n" + cert_str;
            cert_str = "";
        }
    }

    if(result[result.length] != "\n")
        result += "\n";
    result += endCert + "\n";
    return result;
}
