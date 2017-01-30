import Blinder from "./blinding/blinder";
import blinding_util from "./blinding/blinding_util";
import client from "./client";
import pgp from "./pgp/pgp";

if (document && document.getElementById("activate_pseudonym_button")) {

  const button = document.getElementById("activate_pseudonym_button");

  if (button instanceof HTMLElement) {
    button.onclick = async () => {
      const { blinder, packet } = await blinding_util.prepareBlinding();
      await blinder.forgeSignature(packet);

      const key_ascii = await pgp.exportKeyToAsciiWithSignature(packet.target_key, packet);

      // tslint:disable-next-line:no-console
      console.log(key_ascii);
    };
  }
}
