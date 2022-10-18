import "reflect-metadata";
import {createConnection} from "typeorm";
import express from 'express';
import bodyParser from "body-parser";
import multer from 'multer';
import BaseRouter from './routes/index';
import fs from 'fs';
import { Constants } from './constants';

const port = process.env.PORT || 3000;

// create and setup express app
createConnection().then(async () => {
    const app = express();

    app.use(bodyParser.json());
    app.use(multer({ storage: multer.memoryStorage() }).single("file"));
    app.use('/', BaseRouter);

    // set your test device to use http (in Settings->Developer) 
    app.listen(port, () => {
        console.log(`[SERVER] Running at http://localhost:${port}`);
    });
}).catch(error => console.log("TypeORM connection error: ", error));

if (!fs.existsSync(Constants.PASSES_FOLDER)) {
    fs.mkdirSync(Constants.PASSES_FOLDER)
}
