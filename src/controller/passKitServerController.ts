import { Request, Response } from "express";
import { getManager } from "typeorm";
import { Pass } from "../entity/Pass";
import { Registration } from "../entity/Registration";
import { getMaxDateFromArray } from '../util/date';
import { extractToken } from '../util/auth';

const passRepository = () => getManager().getRepository(Pass);
const registrationRepository = () => getManager().getRepository(Registration);

/**
 *  Registering a device to receive push notifications for a pass
    Authorization tokens are specified by each pass
 */
export async function postRegisterDevice(request: Request, response: Response) {
    const pass = await passRepository().findOne({
        passTypeId: request.params.passTypeId,
	serialNumber: request.params.serialNumber,
	authenticationToken: extractToken(request)
    });
    if (pass) {
        let registration = await registrationRepository().findOne(
            { deviceId: request.params.deviceId, pass: pass }
        );
        if (registration) {
            response.sendStatus(200);
        } else {
            registration = new Registration();
            registration.deviceId = request.params.deviceId;
            registration.pushToken = request.body.pushToken;
            registration.pass = pass;
            await registrationRepository().save(registration);
            response.sendStatus(201);
        }
    } else {
        response.sendStatus(401);
    }
}

/**
 *  Handling updates request
 */
export async function getUpdatablePasses(request: Request, response: Response) {
    let passes = await passRepository().createQueryBuilder("pass")
        .innerJoinAndSelect("pass.registrations", "registration")
        .where("pass.passTypeId = :passTypeId", { passTypeId: request.params.passTypeId })
        .andWhere("registration.deviceId = :deviceId", { deviceId: request.params.deviceId })
        .getMany()
    
    const passesUpdatedSince = request.query.passesUpdatedSince;

    if (passesUpdatedSince) {
        passes = passes.filter(pass => pass.updatedAt > new Date(passesUpdatedSince));
    }
    
    if (passes.length > 0) {
        const lastPassUpdated: Date = getMaxDateFromArray(passes.map(pass => pass.updatedAt));
        const serialNumbers = passes.map(pass => pass.serialNumber);

        response.status(200).send({ lastUpdated: lastPassUpdated, serialNumbers: serialNumbers });
    } else {
        response.sendStatus(204);
    }
}

/**
 *  Unregistering a device to receive push notifications for a pass
 */
export async function unregisterDevice(request: Request, response: Response) {
    const pass = await passRepository().findOne({
        passTypeId: request.params.passTypeId,
        serialNumber: request.params.serialNumber,
	authenticationToken: extractToken(request)
    });
    if (pass) {
        const registration = await registrationRepository().findOne(
            { deviceId: request.params.deviceId, pass: pass }
        );
        if (registration) {
            await registrationRepository().delete(registration);
            response.sendStatus(200);
        } else {
            response.sendStatus(401);
        }
    } else {
        response.sendStatus(401);
    }
}

