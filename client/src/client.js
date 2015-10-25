"use strict";

var util = require("./util");

module.exports = {

  /// Constant element ids
  server_public_key_element_id: "server_public_key",
  user_public_key_element_id: "public_key_textarea",
  user_token_element_id: "token_textarea",

   /// Extract users public key from the related textarea
   ///
   /// @return
   ///      public key as openpgp.key object
   getPublicKey: function()
   {
      var public_key_string = this.getPublicKeyString();
      if (public_key_string === null) { return null; }

      var public_key = util.generateKeyFromString(public_key_string);
      if (public_key === null) {
         throw new Error("Could not generate public key. Please check your input.");
      }

      return public_key.keys[0];
   },

   /// Extracts users public key from textarea "public_key_textarea".
   ///
   /// @return
   ///      "public_key_textarea" value as {string} or null if the id is missing
   getPublicKeyString: function()
   {
     var content = util.getTextAreaContent(this.user_public_key_element_id);
     if (util.isString(content)) {
       content = content.trim();
     }

     return content;
   },

   /// Extract users token from textarea "token_textarea"
   ///
   /// @return
   ///   token as openpgp.MPI
   getToken: function()
   {
      var token_string = this.getTokenString();
      if (token_string === null) { return null; }

      var token = util.str2MPI(token_string);

      if (!util.isMPIProbablyPrime(token)) {
         throw new Error("Unsecure Token. Please check your input.");
      }

      return token;
   },

   /// Extracts users token from textarea "token_textarea".
   ///
   /// @return
   ///      "token_textarea" value as {string}
   getTokenString: function()
   {
     var content = util.getTextAreaContent(this.user_token_element_id);
     if (util.isString(content)) {
       content = content.trim();
     }

     return content;
   },

   /// TODO
   getServerPublicKey: function()
   {
      var public_key_string = this.getServerPublicKeyString();
      var public_key = util.generateKeyFromString(public_key_string);

      if (public_key === null) {
         throw new Error("Could not read servers public key. Please reload page.");
      }

      return public_key.keys[0];
   },

  /// TODO
  getServerPublicKeyString: function()
  {
    var element = document.getElementById(this.server_public_key_element_id);
    if (element === null) {
      throw new Error("Couldn't load the server public key. Please reload.");
    }

    return element.innerHTML.trim();
  },

  /// Extracts the public MPIs from the servers public key.
  collectPublicBlindingInformation: function()
  {
    var server_public_key = this.getServerPublicKey();

    return {
      modulus:          server_public_key.primaryKey.mpi[0].data,
      public_exponent:  server_public_key.primaryKey.mpi[1].data
    };
   }
};