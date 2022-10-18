import { Request, Response, Router } from 'express';
import { postRegisterDevice, getUpdatablePasses, unregisterDevice } from '../controller/passKitServerController';
import { createPass, updatePass, getPass } from '../controller/passController';

let router = Router();

/* create a new pass */
router.post('/admin/pass', createPass);


/* update a pass */
router.patch('/admin/pass/:passTypeId/:serialNumber', updatePass);


// Passkit Web Server implementation

/**
 *  Registering a device to receive push notifications for a pass
 */
router.post('/v1/devices/:deviceId/registrations/:passTypeId/:serialNumber', postRegisterDevice);

/**
 *  Handling updates request
 */
router.get('/v1/devices/:deviceId/registrations/:passTypeId', getUpdatablePasses);

/**
 *  Getting the Latest Version of a pass
 */
router.get('/v1/passes/:passTypeId/:serialNumber', getPass);

/**
 *  Unregistering a device to receive push notifications for a pass
 */
router.delete('/v1/devices/:deviceId/registrations/:passTypeId/:serialNumber', unregisterDevice);

/**
 *  Show logs
 */
router.post('/v1/log', (req: Request, res: Response) => {
  console.log(req.body)
});


export default router;
