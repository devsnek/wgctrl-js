'use strict';

const {
  getDevices,
  getDevice,
  addDevice,
  deleteDevice,
  generatePublicKey,
  generatePrivateKey,
  generatePresharedKey,
} = require('bindings')('wg');

module.exports = {
  getDevices,
  getDevice,
  addDevice,
  deleteDevice,
  generatePublicKey,
  generatePrivateKey,
  generatePresharedKey,
};
