# Experimental external MFi provider

`carPlayMfiEndpoint` selects an existing device-backed authentication service through
a local forwarding connection. This is host support only. It does not install a
device service, supply an identity, or establish that an AX520 stock firmware
authenticates successfully.

```json
{
  "carPlayMfiEndpoint": "127.0.0.1:15000"
}
```

The value must be a literal `127.0.0.1:PORT` or `[::1]:PORT` with a nonzero port.
DNS names, LAN addresses, wildcard addresses, and URLs are rejected. Use a verified
SSH local forward to a service on the device; loopback alone does not authenticate
the process listening there. Provisioning that forward and device service is a
separate step. The helper environment carries this setting as `LIVI_MFI_ENDPOINT`.

An empty value preserves the existing files, local I²C, and LIVI Link selection.
A configured endpoint takes precedence over those providers. At helper startup,
LIVI requests the provider's protocol major using the existing bounded MFi network
client and accepts only major 2 or 3. An invalid or unavailable endpoint leaves
authentication unavailable and wired CarPlay bring-up blocked; it never selects
another identity. Start the forward before starting/restarting the helper. If the
provider becomes unavailable later, authentication operations fail through the
normal error path without falling back.

The service must implement the existing `iap2-mfi` network protocol:

| Request | Payload                                | Successful response body          |
| ------- | -------------------------------------- | --------------------------------- |
| `0x01`  | none                                   | Public authentication certificate |
| `0x02`  | big-endian u16 length, challenge bytes | Device-generated signature        |
| `0x03`  | none                                   | One byte: protocol major 2 or 3   |

Every response begins with a status byte (`0` success, `1` error) and a big-endian
u16 body length. The existing client bounds requests to 1–128 challenge bytes,
connects/writes with a two-second timeout, reads with a five-second timeout, and
retries once after an I/O error. A device implementation must enforce its own
algorithm's exact input lengths and serialize access where its native provider
requires it. Private keys remain on the device. No proprietary library, firmware,
certificate, or identity is included in this change.

Protocol availability is not authentication success. Real validation still needs
the phone to accept the authentication exchange, followed by actual video, audio,
touch, and reconnection tests. Direct stock logs and matching binary hashes identify
`PATH_I2C=ly_iap` and Bluetooth callback state 3, traced to receipt of the phone's
iAP2 authentication-success message. The later stock connection timed out.
Subsequent AirPlay authentication, native library ABI/lifecycle in a wrapper, and
any device-local bridge remain unverified. Its web page, Bluetooth pairing, and
`05ac:12a8` USB enumeration alone do not establish authentication or projection.

The current wired receiver discovers Apple VID devices, then requires CarPlay USB
configuration negotiation, usbmux, lockdown, and the carkit service. A stock
adapter presenting the Apple VID may not implement that full path. This setting
does not change the USB protocol or remove authentication checks.

See [AX520 stock authentication analysis](AX520-STOCK-AUTH.md) for the static
control-flow evidence and the remaining device-side validation requirements.
