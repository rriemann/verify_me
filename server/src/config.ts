const base_dir = __dirname + "/../../../client";
const key_base_dir = base_dir + "/test/sample_keys";

export default {

  client: {
    base_dir,
  },

  keys: {

    ecc: {

      passphrase: "verifyme",

      private_key: key_base_dir + "/ecc_nist_p_256_priv.asc",
      public_key: key_base_dir + "/ecc_nist_p_256_pub.asc",
    },

    rsa: {

      passphrase: "verifyme",

      private_key: key_base_dir + "/rsa_1024_priv.asc",
      public_key: key_base_dir + "/rsa_1024_pub.asc",
    },
  },
};
