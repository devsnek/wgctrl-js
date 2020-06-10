# wgctrl-js

```
$ npm i wgctrl
```

```js
import { getDevices, getDevice, setDevice } from 'wgctrl';

// Get the current WireGuard device names.
console.log(getDevices()); // [ 'device 1', 'device 2' ]

// Get the configuration of a specific device.
const d = getDevice('device 1');


// Add a peer and set the configuration:
d.peers.push({
  publicKey: 'abc',
  presharedKey: 'def',
  endpoint: '192.51.100.127:1234',
  presistentKeepaliveInterval: 25,
  allowedIPs: [
    '10.137.137.0/24',
  ],
});

// Set the configuration of a specific device.
setDevice(d);
```
