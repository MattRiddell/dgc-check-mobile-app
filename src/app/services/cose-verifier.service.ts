import { Injectable } from '@angular/core';
import { Certificate } from '../x509/x509.js';

import { SCHEMA } from '../../resources/json/DGC-all-schemas-combined';

const rawHash = require("sha256-uint8array").createHash;

const zlib = require('pako');
var cbor = require('cbor-redux');
var sign = require('../cose-js/sign.js');
var validate = require('jsonschema').validate;

/* TODO CHECK IF WE HAVE A BETTER WAY TO IMPORT */
declare var require: any;
//declare const Buffer;
const base45 = require("../../../node_modules/base45-js/lib/base45-js.js");

@Injectable({
  providedIn: 'root'
})
export class CoseVerifierService {

  public PREFIX: string = 'HC1:';

  constructor() {}

  verify(data) {

    data = this.removePrefix(data);
    data = base45.decode(data);

    console.log(data.toString());

    // Zlib magic headers:
    // 78 01 - No Compression/low
    // 78 9C - Default Compression
    // 78 DA - Best Compression
    if (data[0] == 0x78) {
      data = zlib.inflate(new Uint8Array(data));
    }
    console.log("------1");
    console.log(data);
    console.log("------2");

    // Sample PEM
    const cert = Certificate.fromPEM(Buffer.from(
      // '-----BEGIN CERTIFICATE-----\n' +
      // 'MIIEHjCCAgagAwIBAgIUM5lJeGCHoRF1raR6cbZqDV4vPA8wDQYJKoZIhvcNAQELBQAwTjELMAkGA1UEBhMCSVQxHzAdBgNVBAoMFk1pbmlzdGVybyBkZWxsYSBTYWx1dGUxHjAcBgNVBAMMFUl0YWx5IERHQyBDU0NBIFRFU1QgMTAeFw0yMTA1MDcxNzAyMTZaFw0yMzA1MDgxNzAyMTZaME0xCzAJBgNVBAYTAklUMR8wHQYDVQQKDBZNaW5pc3Rlcm8gZGVsbGEgU2FsdXRlMR0wGwYDVQQDDBRJdGFseSBER0MgRFNDIFRFU1QgMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDSp7t86JxAmjZFobmmu0wkii53snRuwqVWe3/g/wVz9i306XA5iXpHkRPZVUkSZmYhutMDrheg6sfwMRdql3aajgb8wgbwwHwYDVR0jBBgwFoAUS2iy4oMAoxUY87nZRidUqYg9yyMwagYDVR0fBGMwYTBfoF2gW4ZZbGRhcDovL2NhZHMuZGdjLmdvdi5pdC9DTj1JdGFseSUyMERHQyUyMENTQ0ElMjBURVNUJTIwMSxPPU1pbmlzdGVybyUyMGRlbGxhJTIwU2FsdXRlLEM9SVQwHQYDVR0OBBYEFNSEwjzu61pAMqliNhS9vzGJFqFFMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAIF74yHgzCGdor5MaqYSvkS5aog5+7u52TGggiPl78QAmIpjPO5qcYpJZVf6AoL4MpveEI/iuCUVQxBzYqlLACjSbZEbtTBPSzuhfvsf9T3MUq5cu10lkHKbFgApUDjrMUnG9SMqmQU2Cv5S4t94ec2iLmokXmhYP/JojRXt1ZMZlsw/8/lRJ8vqPUorJ/fMvOLWDE/fDxNhh3uK5UHBhRXCT8MBep4cgt9cuT9O4w1JcejSr5nsEfeo8u9Pb/h6MnmxpBSq3JbnjONVK5ak7iwCkLr5PMk09ncqG+/8Kq+qTjNC76IetS9ST6bWzTZILX4BD1BL8bHsFGgIeeCO0GqalFZAsbapnaB+36HVUZVDYOoA+VraIWECNxXViikZdjQONaeWDVhCxZ/vBl1/KLAdX3OPxRwl/jHLnaSXeqr/zYf9a8UqFrpadT0tQff/q3yH5hJRJM0P6Yp5CPIEArJRW6ovDBbp3DVF2GyAI1lFA2Trs798NN6qf7SkuySz5HSzm53g6JsLY/HLzdwJPYLObD7U+x37n+DDi4Wa6vM5xdC7FZ5IyWXuT1oAa9yM4h6nW3UvC+wNUusW6adqqtdd4F1gHPjCf5lpW5Ye1bdLUmO7TGlePmbOkzEB08Mlc6atl/vkx/crfl4dq1LZivLgPBwDzE8arIk0f2vCx1+4=\n' +
      // '-----END CERTIFICATE-----\n'
`-----BEGIN CERTIFICATE-----
MIIBXjCCAQUCEEHZyiFzP7SRbDOGXUjt6sUwCgYIKoZIzj0EAwIwMjEjMCEGA1UE
AwwaTmF0aW9uYWwgQ1NDQSBvZiBGcmllc2xhbmQxCzAJBgNVBAYTAkZSMB4XDTIx
MDYxNTE4MjgxMloXDTI2MDQzMDE4MjgxMlowNjEnMCUGA1UEAwweRFNDIG51bWJl
ciB3b3JrZXIgb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABGfgmXo+9WxQTM7XTBRXPA1nLirRiGdqnyrql/6Q39/fWNc9
o3yfsBfv+QrJZjuedz0j5cEFcLRgjZsgvsPWfCEwCgYIKoZIzj0EAwIDRwAwRAIg
Ivhc5nZ3vzT440SeeBenV/uCy4v23A2uqwYSO4zLOLYCIEqprnZIs4ENzoHB0WaP
pMJ5LcMjiQ24+2Rs2lcW5iCF
-----END CERTIFICATE-----
        `
    ));

    var bytes = new Uint8Array(cert.raw);

    const fingerprint = rawHash().update(cert.raw).digest();
    const keyID = fingerprint.slice(0,8)

    // Highly ES256 specific - extract the 'X' and 'Y' for verification
    //
    let pk = cert.publicKey.keyRaw
    const keyB = Buffer.from(pk.slice(0, 1))
    const keyX = Buffer.from(pk.slice(1, 1+32))
    const keyY = Buffer.from(pk.slice(33,33+32))

    const verifier = { 'key': { 'x': keyX, 'y': keyY,  'kid': keyID } };
    console.log("------3");
    console.log({verifier, cert});
    console.log("------4");
    return sign.verify(data, verifier)
    .then((buf) => {
      let decoded = cbor.decode(this.typedArrayToBuffer(buf));
      console.log("------5");
      console.log(JSON.stringify(decoded, null, 5));

      return decoded;
    });
  }

  validateSchema(json) {
    console.log('Schema validation');
    let result = validate(json, SCHEMA);
    console.log(result);

    return result;
  }

  getCwtHeaderData(data) {
    console.log()
    console.log({data});
    console.log()
    data = this.removePrefix(data);
    console.log()
    console.log({data});
    console.log()
    data = base45.decode(data);
    console.log()
    console.log({data});
    console.log()
    if (data[0] == 0x78) {
      data = zlib.inflate(new Uint8Array(data));
    }
    if (data === undefined) {
      throw Error('Data badly compressed');
    }
    console.log(data.toString());
    let [p, u, plaintext, signers] = cbor.decode(this.typedArrayToBuffer(data));
    var cwt = cbor.decode(this.typedArrayToBuffer(plaintext));
    console.log({cwt, plaintext, p, u, signers})
    console.log(JSON.stringify(cwt, null, 5));
    console.log("=======")
    console.log("=======")
    return cwt;
  }

  typedArrayToBuffer(array: Uint8Array): ArrayBuffer {
    return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
  }

  removePrefix(data) {
    if (data.startsWith(this.PREFIX)) {
      return data.substring(this.PREFIX.length);
    } else {
      return data;
    }
  }
}
