# Changelog

## v0.1.1

- Fix a data race on the shared encode/encrypt buffers: a send abandoned by its
  context while the writer goroutine was still writing no longer lets the next
  send re-encode over that packet (the race was reported in `session.encrypt`
  under `-race`; it also exists upstream in CloudSoda/go-smb2).

## v0.1.0

- `Negotiator.RequireEncryption`, `Session.Encrypted()`, `Share.Encrypted()`.
