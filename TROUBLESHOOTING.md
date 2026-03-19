# Hoot Troubleshooting Guide

Common errors and how to fix them.

## Connection Errors

### "failed to connect to any relay"

**Cause:** All configured relays are unreachable.

**Solutions:**
1. Check your internet connection
2. Verify relay URLs in `relays.txt`:
   ```bash
   cat ~/.config/nostr-cli/relays.txt
   ```
3. Try default relays:
   ```bash
   echo -e "wss://relay.damus.io\nwss://relay.nostr.band\nwss://nostr.wine" > ~/.config/nostr-cli/relays.txt
   ```
4. Check if a relay is online:
   ```bash
   curl -I https://relay.damus.io
   ```

---

### "failed to publish to any relay"

**Cause:** Event was created but couldn't be published to any relay.

**Solutions:**
1. Try with longer timeout:
   ```bash
   export HOOT_PUBLISH_TIMEOUT=30s
   hoot -m "Your message"
   ```
2. Check relay status in output
3. Verify relay URLs are valid websocket URLs (`wss://`)

---

## Authentication Errors

### "password verification failed"

**Cause:** Wrong password or corrupted key file.

**Solutions:**
1. Double-check password (case-sensitive, no extra spaces)
2. Verify key file exists:
   ```bash
   ls -la ~/.config/nostr-cli/nostr_key.enc
   ```
3. If corrupted, recreate with your nsec:
   ```bash
   hoot -s -k nsec1...
   ```

---

### "no active session or local key"

**Cause:** No private key available for signing.

**Solutions:**
1. Store your key first:
   ```bash
   hoot -s -k nsec1...
   ```
2. Or set `HOOT_PASSWORD` env var and run again

---

## Profile Errors

### "profile not found"

**Cause:** No kind 0 (profile) event found for your pubkey.

**Solutions:**
1. Create a profile:
   ```bash
   hoot -u '{"name":"YourName","about":"Your bio"}'
   ```

---

### "failed to sign event"

**Cause:** Private key issue or NIP-46 session expired.

**Solutions:**
1. Verify your key is stored:
   ```bash
   hoot  # Should show your npub
   ```
2. If using NIP-46, reconnect your signer app

---

## Lightning / Tipping Errors

### "failed to get NWC URI (use -nwc to set it)"

**Cause:** No NWC wallet configured.

**Solutions:**
1. Get NWC URI from your wallet (Alby, Mutiny, etc.)
2. Configure it:
   ```bash
   hoot -nwc "nostr+walletconnect://..."
   ```

---

### "failed to resolve lightning address"

**Cause:** Invalid or unreachable Lightning address (LUD-16).

**Solutions:**
1. Verify the Lightning address format: `user@domain.com`
2. Check if the user has a valid `lud16` in their profile:
   ```bash
   hoot -p  # View your profile
   ```

---

### "payment failed"

**Cause:** Wallet rejected the payment or invoice expired.

**Solutions:**
1. Check your wallet balance
2. Verify the invoice amount
3. Try a smaller tip amount

---

## Relay Errors

### "Error connecting to relay"

**Cause:** Relay is offline, rate-limiting, or URL is invalid.

**Solutions:**
1. Try a different relay
2. Check URL format (must start with `wss://`)
3. Increase connection timeout:
   ```bash
   export HOOT_RELAY_CONNECT_TIMEOUT=30s
   ```

---

### "Skipping event with invalid timestamp"

**Cause:** Event has a timestamp outside valid range (2020-2100).

**Solutions:**
1. This is a safety feature - ignore malformed events
2. Usually indicates spam or corrupted data

---

## Environment Variable Issues

### Timeouts not applying

**Cause:** Invalid duration format.

**Solutions:**
Use proper duration format:
- `30s` - 30 seconds
- `1m` - 1 minute
- `2m30s` - 2 minutes 30 seconds

```bash
export HOOT_QUERY_TIMEOUT=30s
export HOOT_PUBLISH_TIMEOUT=1m
```

---

### "Invalid HOOT_BCRYPT_COST value"

**Cause:** Cost value outside valid range.

**Solutions:**
Use a value between 4 and 31:
```bash
export HOOT_BCRYPT_COST=12  # Good default
```

Higher values = more secure but slower.

---

## Getting Help

1. Check the [README.md](README.md) for usage examples
2. Open an issue: https://github.com/oth-body/hoot/issues
3. Include error message and steps to reproduce
