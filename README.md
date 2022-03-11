## XMR recovery tool

Work in progress.

Scans subaddress accounts for outputs from given transaction that belong to the wallet.

### Build

```
git clone https://github.com/tobtoht/xmr-recovery.git
cd xmr-recovery
git submodule update --init --recursive
mkdir build
cd build
cmake -DARCH=default ..
cmake --build . --target recovery
```

### Config format

Save `config.json` relative to the recovery binary.

```json
{
  "primaryAddress": "",
  "secretSpendKey": "",
  "secretViewKey": "",
  "prunedTxHex": "",
  "minorIndexMax": 100,
  "threads": 8
}
```