import { Request } from 'express';
import fs from 'fs-extra';

export function extractToken(req: Request): string {
    let token = '';
    if (req.headers && req.headers.authorization) {
        const parts = req.headers.authorization.split(' ');
        if (parts.length === 2 && parts[0] === 'ApplePass') {
            token = parts[1];
	}
    }
    if (!token && req.query && req.query.authenticationToken) {
	token = req.query.authenticationToken;
    }
    return token;
}

export function getKeyPassphrase(): string {
    return process.env.KEY_PASSPHRASE_FILE ? (fs.readFileSync(process.env.KEY_PASSPHRASE_FILE || '', 'utf-8')).replace(/(\r\n|\n|\r)/gm, '') : '';
}
