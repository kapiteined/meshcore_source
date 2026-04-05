# Vendoring MeshCore ed25519 sources (exact match)

Deze patch verwacht dat de **exacte** ed25519 bronnen uit de MeshCore firmware aanwezig zijn in:

`mcframe/src/crypto/ed25519/`

Voer het script uit om de bestanden 1-op-1 te kopiëren uit jouw firmware checkout.

## Gebruik

```bash
cd mcframe/src/crypto/ed25519
./vendor_ed25519_from_meshcore.sh ~/MeshCore
```
