# SFrame.ts

Typescript library implementing the SFrame end to end encryption based on webcrypto.

## Differences from the sframe draft

- ratcheting is not implemented
- keyIds are used as senderIds
- IV contains the keyId and the frame counter to ensure uniquenes when using same encryption key for all participants

## Keying

This library does not provide any keying mechanism, but it must be provide by the application instead.

Unlike the sframe draft, this library requires each participant to have a numeric `senderId` that will be used as `keyId` in the sframe header.

## Example

Check the `example` directory for a loopback example implementation.

## References

<https://datatracker.ietf.org/doc/draft-ietf-sframe-enc/>

## License

BSD-3-Clause
