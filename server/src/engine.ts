"use strict";

import { readFile } from "fs";
import { assert, check } from "verifyme_utility";

/**
 * Template engine that replaces the a key place holder with a given ascii key string.
 *
 * @param {string} file_path
 *    Path to the requested html file.
 *
 * @param {object} options
 *    Object containing the ascii key string.
 *
 * @param {function.<Error, string>} callback
 *    A callback given from express which receives
 *    an Error or the manipulated html string.
 *
 * @return {*}
 *    Result of the given callback.
 */
export default function customHtmlEngine(file_path: string,
                                         options: { public_key: string },
                                         callback: (error: Error|null, content?: string) => void ): void {
  assert(check.isString(file_path));
  assert(check.isObject(options));
  assert(check.isFunction(callback));

  readFile(file_path, (err, content) => {

    if (err || !options.hasOwnProperty("public_key")) {
      return callback(new Error(err.message));
    }

    const rendered = content.toString()
      .replace("{public_key}", options.public_key);

    return callback(null, rendered);
  });
}
