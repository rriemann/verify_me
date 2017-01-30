"use strict";

import { json } from "body-parser";
import * as express from "express";

import config from "./config";
import customHtmlEngine from "./engine";
import keys from "./keys";
import routes from "./routes";

const app = express();

// Allow static css and js files
app.use("/css", express.static(config.client.base_dir + "/css"));
app.use("/js", express.static(config.client.base_dir + "/dist"));

// to support JSON-encoded bodies
app.use(json());

// Set custom view engine
app.set("views", config.client.base_dir + "/views");
app.set("view engine", "html");
app.engine("html", customHtmlEngine);

// Wait with route setup until all keys are loaded.
Promise.all([keys.rsa_promise, keys.ecc_promise])
  .then((values) => {

    app.get("/rsa", routes.rsa.renderIndex);
    app.post("/rsa", routes.rsa.signBlindedMessage);

    app.get("/ecdsa/andreev", routes.ecdsa.andreev.renderIndex);
    app.post("/ecdsa/andreev/init", routes.ecdsa.andreev.initBlindingAlgorithm);
    app.post("/ecdsa/andreev/sign", routes.ecdsa.andreev.signBlindedMessage);

    app.get("/ecdsa/butun", routes.ecdsa.butun.renderIndex);
    app.post("/ecdsa/butun/init", routes.ecdsa.butun.initBlindingAlgorithm);
    app.post("/ecdsa/butun/sign", routes.ecdsa.butun.signBlindedMessage);

  })
  .catch((error) => {
    /* tslint:disable:no-console */
    console.log("");
    console.error("> Error: Server could not load keys.");
    console.error("> Reason: " + error);
    console.error("> Reason: " + error.stack);
    console.log("");
    /* tslint:enable:no-console */
  });

/// Run Server
const server = app.listen(8888, () => {
  /* tslint:disable:no-console */
  console.log("");
  console.log("> Start Express Server");
  console.log("> Listening on port %d", server.address().port);
  console.log("");
  /* tslint:enable:no-console */
});
