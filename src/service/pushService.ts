import * as apn from "apn";
import { Constants } from '../constants';
import { getKeyPassphrase } from '../util/auth';

export async function sendPush(deviceTokens: string[], topic: string) {

    const options = {
	cert: Constants.CERT_FOLDER + "/" + topic + Constants.CERT_EXT,
	key: Constants.CERT_FOLDER + "/" + topic + Constants.KEY_EXT,
	passphrase: getKeyPassphrase(),
        production: true
    }

    const apnProvider = new apn.Provider(options);

    let note = new apn.Notification();
    note.payload = {};
    note.contentAvailable = true;
    note.topic = topic;

    apnProvider.send(note, deviceTokens).then((response) => {
        console.log(response)
    });

    apnProvider.shutdown();

}
