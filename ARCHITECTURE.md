# Otti Production Architecture

## Client
Next.js/React can replace the current static client without changing the realtime event contract.

## Realtime
WebSocket endpoint:
- join
- message
- typing
- read
- react
- edit
- delete
- dive

## Scale-out target

Users
  -> CDN / Load Balancer
  -> multiple Otti application instances
  -> Redis pub/sub
  -> PostgreSQL

## Privacy

DIVE is a client-side privacy state. Camera-based peeking detection should remain on-device and permissioned; camera frames should not be uploaded by default.

## Deployment

The current repository is deliberately deployable as a Node application, but production infrastructure should be configured separately from source code and secrets must never be committed.
