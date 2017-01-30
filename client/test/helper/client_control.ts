"use strict";

import { assert } from "chai"
import client from"../../src/client"

/// Utility API for html interaction.
export const controls = {
  
  serverPublicKey(): string {
    
    const element = document.getElementById(client.server_public_key_element_id);
    
    return (element != null) ? element.innerHTML : "";
  },

  setServerPublicKey(val: string) {
    const element = document.getElementById(client.server_public_key_element_id);
    if (element == null) {
      return;
    }

    element.innerHTML = val;
  },

  userPublicKeyString(): string {
    const element = <HTMLTextAreaElement> document.getElementById(client.user_public_key_element_id);
    return (element != null) ? element.value : "";
  },

  setUserPublicKeyString(val: string) {

    const element = <HTMLTextAreaElement> document.getElementById(client.user_public_key_element_id);
    if (element == null) {
      return;
    }

    element.value = val;
  },

  userTokenString(): string {
    const element = <HTMLTextAreaElement> document.getElementById(client.user_token_element_id);
    return (element != null) ? element.value : "";
  },

  setUserTokenString(val: string) {
    const element = <HTMLTextAreaElement> document.getElementById(client.user_token_element_id);
    if (element == null) {
      return;
    }

    element.value = val;
  },

  loadFixture: function(fixture: string): boolean {
    
    if (!window.hasOwnProperty("__html__")) {
      assert.fail("Missing: " + fixture)
    }

    document.body.innerHTML = (<any>window).__html__[fixture];
    return true;
  }
};