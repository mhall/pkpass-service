import { Request, Response } from "express";
import { Template, Pass as WalletPass } from "@walletpass/pass-js";
import fs from "fs-extra";
import { getManager } from "typeorm";
import { Pass } from "../entity/Pass";
import { sendPush } from "../service/pushService"
import { Registration } from '../entity/Registration';
import { Constants } from '../constants';
import { getKeyPassphrase, extractToken } from '../util/auth';
import { createHash } from 'crypto';

const passRepository = () => getManager().getRepository(Pass);
const registrationRepository = () => getManager().getRepository(Registration);

export async function createPass(request: Request, response: Response) {
    try {
	if (!request.file) {
	    response.sendStatus(400);
	    return;
	}

	const template = await Template.fromBuffer(request.file.buffer);

	template.setCertificate(fs.readFileSync(Constants.CERT_FOLDER + "/" + template.passTypeIdentifier + Constants.CERT_EXT, 'utf-8'));
	template.setPrivateKey(fs.readFileSync(Constants.CERT_FOLDER + "/" + template.passTypeIdentifier + Constants.KEY_EXT, 'utf-8'), getKeyPassphrase());

	const pass = template.createPass();

	pass.webServiceURL = Constants.WEB_SERVICE_URL;

        let passEntity = await passRepository().findOne({
            passTypeId: pass.passTypeIdentifier,
            serialNumber: pass.serialNumber
	});

	if (passEntity) {
	    pass.authenticationToken = passEntity.authenticationToken;
	} else {
	    pass.authenticationToken = Math.random().toString(36).substr(2,10) + Math.random().toString(36).substr(2,10);
	}

	pass.validate();

	const passHash = await getPassHash(pass);
	if (!passEntity || passEntity.hash != passHash) {
            const buf = await pass.asBuffer();
	    await fs.writeFile(`${Constants.PASSES_FOLDER}/${template.passTypeIdentifier}_${template.serialNumber}${Constants.PASS_EXT}`, buf);
	}

	if (passEntity) {
	    if (passEntity.hash != passHash) {
		passEntity.updatedAt = new Date();
		passEntity.hash = passHash;
                const pushTokens = await getDevicePushTokens(passEntity);
		pushTokens && sendPush(pushTokens, passEntity.passTypeId);
	    } else {
		response.sendStatus(304);
		return;
	    }
        } else {
            passEntity = new Pass();
            passEntity.passTypeId = pass.passTypeIdentifier || '';
	    passEntity.serialNumber = pass.serialNumber || '';
	    passEntity.authenticationToken = pass.authenticationToken || '';
	    passEntity.updatedAt = new Date();
	    passEntity.hash = passHash;
	}
        await passRepository().manager.save(passEntity);

	response.status(201).send({ passTypeIdentifier: passEntity.passTypeId,
				    serialNumber: passEntity.serialNumber,
				    authenticationToken: passEntity.authenticationToken, 
				    passURL: Constants.WEB_SERVICE_URL + "/v1/passes/" + passEntity.passTypeId +
					"/" + passEntity.serialNumber + "?authenticationToken=" + passEntity.authenticationToken });

    } catch (error) {
	console.log(error);
        response.status(400).send({ err: error });
    }

}

export async function updatePass(request: Request, response: Response) {
    try {
        let passEntity = await passRepository().findOne({
            passTypeId: request.params.passTypeId,
            serialNumber: request.params.serialNumber
        });

	if (!passEntity) {
	    response.sendStatus(404);
	    return;
	}

	const template = await Template.fromBuffer(fs.readFileSync(`${Constants.PASSES_FOLDER}/${request.params.passTypeId}_${request.params.serialNumber}${Constants.PASS_EXT}`));

	template.setCertificate(fs.readFileSync(Constants.CERT_FOLDER + "/" + template.passTypeIdentifier + Constants.CERT_EXT, 'utf-8'));
	template.setPrivateKey(fs.readFileSync(Constants.CERT_FOLDER + "/" + template.passTypeIdentifier + Constants.KEY_EXT, 'utf-8'), getKeyPassphrase());

	const pass = template.createPass();

	if (pass.barcodes && pass.barcodes[0]) {
	    pass.barcodes[0].message = (request.body.hasOwnProperty("barcodeMessage")) ? request.body.barcodeMessage : "";
	    pass.barcodes[0].altText = (request.body.hasOwnProperty("barcodeAltText")) ? request.body.barcodeAltText : "";
	}
	pass.expirationDate = (request.body.hasOwnProperty("expirationDate")) ? request.body.expirationDate : "";

	pass.validate();

	const passHash = await getPassHash(pass);
	if (passEntity.hash != passHash) {
            const buf = await pass.asBuffer();
            await fs.writeFile(`${Constants.PASSES_FOLDER}/${template.passTypeIdentifier}_${template.serialNumber}${Constants.PASS_EXT}`, buf);
	    passEntity.updatedAt = new Date();
	    passEntity.hash = passHash;
            const pushTokens = await getDevicePushTokens(passEntity);
	    pushTokens && sendPush(pushTokens, passEntity.passTypeId);
            await passRepository().manager.save(passEntity);
	} else {
	    response.sendStatus(304);
	    return;
	}

	response.status(200).send({ passTypeIdentifier: passEntity.passTypeId, serialNumber: passEntity.serialNumber });

    } catch (error) {
	console.log(error);
        response.status(400).send({ err: error });
    }

}

export async function getPass(request: Request, response: Response) {
    let passEntity = await passRepository().findOne({
        passTypeId: request.params.passTypeId,
        serialNumber: request.params.serialNumber,
        authenticationToken: extractToken(request)
    });

    if (passEntity) {
	if (request.headers && request.header("if-modified-since")) {
	    if (passEntity.updatedAt <= new Date(request.header("if-modified-since") || 0)) {
		response.sendStatus(304);
		return;
	    }
	}

        try {
            response.setHeader("Content-Type", Constants.PKPASS_CONTENT_TYPE);
            response.sendFile(`${Constants.PASSES_FOLDER}/${request.params.passTypeId}_${request.params.serialNumber}${Constants.PASS_EXT}`, { root: "./" })
        } catch (error) {
            response.status(403).send({ err: error });
        }
    } else {
	response.sendStatus(401);
    }
}

/**
 *  Get push tokens registered on the pass
 */
async function getDevicePushTokens(pass: Pass) {
    let registrations = await registrationRepository().find({ where: { pass: pass }, select: ['pushToken'] });
    return registrations.map(registration => registration.pushToken);
}

/**
 *  Get hash of the pkpass manifest file
 *  
 *  adapted from walletpass/pass-js Pass.asBuffer()
 */
async function getPassHash(pass: WalletPass) {
    const files = [] as { path: string; data: Buffer | string }[];

    files.push({ path: 'pass.json', data: Buffer.from(JSON.stringify(pass)) });
    files.push(...pass.localization.toArray());
    files.push(...(await pass.images.toArray()));

    const manifestJson = JSON.stringify(
      files.reduce(
        (res, { path, data }) => {
          res[path] = getBufferHash(data);
          return res;
        },
        {} as { [k: string]: string },
      ),
    );

    return getBufferHash(Buffer.from(manifestJson));
}

function getBufferHash(buffer: Buffer | string): string {
  const sha = createHash('sha1');
  sha.update(buffer);
  return sha.digest('hex');
}
