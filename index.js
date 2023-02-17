import express from 'express';
import https from 'https';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { validate } from 'jsonschema';
import jsonwebtoken from 'jsonwebtoken';
import moment from 'moment';
import md5 from 'md5';
import forge from 'node-forge';
import hexToDecimal from 'biguint-format';
import jsrsasign from 'jsrsasign';
import * as Url from 'url';
import bodyParser from 'body-parser';
import dotenv from 'dotenv'

dotenv.config()

const __filename = Url.fileURLToPath(import.meta.url);
const __dirname = Url.fileURLToPath(new URL('.', import.meta.url));


const url = 'https://blagajne-test.fu.gov.si:9002/v1/cash_registers';
const dtf = 'Y-MM-DD[T]HH:mm:ss[Z]';

const tlsCertFile = path.resolve(__dirname, 'blagajne-test.fu.gov.si.cer');
const myCertFile = path.resolve(__dirname, '10596631-1.p12');
const passphrase = '3WTOPOGY2CN9';
const fursCertPemFile = path.resolve(__dirname, 'DavPotRacTEST.cer');

const app = express();
// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))

// parse application/json
app.use(bodyParser.json())

const httpsAgent = new https.Agent({
    rejectUnauthorized: false,
    ca: fs.readFileSync("./blagajne-test.fu.gov.si.cer"),
    // ca: fs.readFileSync("./ca.pem"),
    minVersion: "TLSv1.2",
    pfx: fs.readFileSync(`./${process.env.TAXNUMBER}-1.p12`),
    passphrase: process.env.PASSPHRASE,
    json: true
});

const TaxNumber = parseInt(process.env.TAXNUMBER);

// Parse pem and data from p12
let key;
const p12Der = forge.util.decode64(fs.readFileSync(myCertFile).toString('base64'));
const p12Asn1 = forge.asn1.fromDer(p12Der);
const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, passphrase);
const bags = p12.getBags({ bagType: forge.pki.oids.certBag });
const cert = bags[forge.pki.oids.certBag][0];

// Serial number
let serial = hexToDecimal(cert['cert']['serialNumber'], 'dec');
// Header issuer and subject
const certCNs = {
    'issuer_name': cert['cert']['issuer'],
    'subject_name': cert['cert']['subject'],
}


const pkcs12Asn1 = forge.asn1.fromDer(p12Der);
const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, false, passphrase);
let map = {};

for (let sci = 0; sci < pkcs12.safeContents.length; ++sci) {
    let safeContents = pkcs12.safeContents[sci];

    for (let sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
        let safeBag = safeContents.safeBags[sbi];
        let localKeyId = null;

        if (safeBag.attributes.localKeyId) {
            localKeyId = forge.util.bytesToHex(safeBag.attributes.localKeyId[0]);

            if (!(localKeyId in map)) {
                map[localKeyId] = {
                    privateKey: null,
                    certChain: [],
                };
            }
        } else {
            continue;
        }

        if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
            map[localKeyId].privateKey = safeBag.key;
        } else if (safeBag.type === forge.pki.oids.certBag) {
            map[localKeyId].certChain.push(safeBag.cert);
        }
    }
}

for (let localKeyId in map) {
    let entry = map[localKeyId];

    if (entry.privateKey) {
        let privateKeyP12Pem = forge.pki.privateKeyToPem(entry.privateKey);
        key = privateKeyP12Pem;
    }
}



let header = {
    alg: 'RS256',
    subject_name: '',
    issuer_name: '',
    serial,
}

const cnTypes = ['subject_name', 'issuer_name'];

cnTypes.forEach(t => {
    for (let i = 0; i < certCNs[t].attributes.length; i++) {
        let attributes = certCNs[t].attributes[i];

        let tName = 'name';
        if ('shortName' in attributes) tName = 'shortName';

        header[t] = header[t] + ',' + attributes[tName] + '=' + attributes['value'];
    }

    header[t] = header[t].substring(1);
});





const getToken = async (payload) => {

    // Validate payload
    let schema = path.resolve(__dirname, 'FiscalVerificationSchema.json');
    schema = JSON.parse(fs.readFileSync(schema));
    const validation = validate(payload, schema);

    if (!!validation.errors && validation.errors.length) {
        console.log(validation.errors);
        throw (validation.errors);
    }

    // Generate JWT
    let token = jsonwebtoken.sign(payload, key, { header, algorithm: 'RS256', noTimestamp: true });
    return token;
}





app.get('/', async (req, res) => {
    try {
        let odg = await axios.post(`${url}/echo`, { "EchoRequest": "furs" }, { httpsAgent });
        res.json(odg.data);
    }
    catch (e) {
        console.log(e);
        res.json({ "error": e });
    }
});

app.post('/register', async (req, res) => {
    const { BusinessPremiseID, CadastralNumber, BuildingNumber, BuildingSectionNumber, Street, HouseNumber, HouseNumberAdditional, Community, City, PostalCode } = req.body;
    const premise = {
        BusinessPremiseRequest: {
            Header: {
                MessageID: uuidv4(),
                DateTime: moment().format(dtf),
            },
            BusinessPremise: {
                TaxNumber,
                BusinessPremiseID,
                BPIdentifier: {
                    RealEstateBP: {
                        PropertyID: {
                            CadastralNumber,
                            BuildingNumber,
                            BuildingSectionNumber
                        },
                        Address: {
                            Street,
                            HouseNumber,
                            HouseNumberAdditional,
                            Community,
                            City,
                            PostalCode
                        }
                    }
                },
                // ValidityDate: moment().format('Y-MM-DD'),
                ValidityDate: moment().format(dtf),
                SoftwareSupplier: [{
                    TaxNumber
                }],
            }
        }
    }

    try {
        let token = await getToken(premise);
        let odg = await axios.post(`${url}/invoices/register`, { token }, {
            httpsAgent, headers: {
                'Content-Type': 'application/json; UTF-8',
            }
        });
        const response = jsonwebtoken.verify(odg.data.token, fs.readFileSync(fursCertPemFile), { algorithms: ['RS256'] });
        res.json(response);
    } catch (error) {
        console.log(error);
        res.json({ "error": error.response.data })
    }
});

const generateZOI = async (IssueDateTime, InvoiceNumber, BusinessPremiseID, ElectronicDeviceID, InvoiceAmount) => {

    // Generate ZOI value
    let ZOI = '' + TaxNumber + IssueDateTime + InvoiceNumber + BusinessPremiseID + ElectronicDeviceID +
        InvoiceAmount;

    let sig = new jsrsasign.KJUR.crypto.Signature({ alg: 'SHA256withRSA' });
    sig.init(key);
    sig.updateString(ZOI);

    ZOI = md5(sig.sign);

    console.log('ZOI:', ZOI);

    return ZOI;
}


app.post('/invoice', async (req, res) => {

    const { BusinessPremiseID, ElectronicDeviceID, InvoiceNumber, InvoiceAmount, TaxRate, TaxableAmount, TaxAmount } = req.body;


    const IssueDateTime = moment().utc().format(dtf);

    const ZOI = await generateZOI(IssueDateTime, InvoiceNumber, BusinessPremiseID, ElectronicDeviceID, InvoiceAmount);


    const invoice = {
        InvoiceRequest: {
            Header: {
                MessageID: uuidv4(),
                DateTime: IssueDateTime
            },
            Invoice: {
                TaxNumber,
                IssueDateTime,
                NumberingStructure: 'B',
                InvoiceIdentifier: {
                    BusinessPremiseID,
                    ElectronicDeviceID,
                    InvoiceNumber
                },
                InvoiceAmount,
                PaymentAmount: InvoiceAmount,
                TaxesPerSeller: [{
                    VAT: [{
                        TaxRate,
                        TaxableAmount,
                        TaxAmount,
                    }]
                }],
                OperatorTaxNumber: TaxNumber,
                ProtectedID: ZOI,
            }
        }
    };
    try {
        let token = await getToken(invoice);
        let odg = await axios.post(`${url}/invoices`, { token }, {
            httpsAgent, headers: {
                'Content-Type': 'application/json; UTF-8',
            }
        });
        const response = jsonwebtoken.verify(odg.data.token, fs.readFileSync(fursCertPemFile), { algorithms: ['RS256'] });
        res.json({ response, ZOI });
    } catch (error) {
        console.log(error);
        res.json({ "error": error.response.data })
    }


});

app.listen(3000);
console.log("Listening on port 3000!");