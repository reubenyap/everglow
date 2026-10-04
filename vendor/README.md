# Pinned proof backend

`lazer/` comes from `lazer-crypto/lazer` commit
`3330e487228f633eceb322807b13a596b516770f`, downloaded from:

https://codeload.github.com/lazer-crypto/lazer/tar.gz/3330e487228f633eceb322807b13a596b516770f

The source archive SHA-256 is
`1714a260a3a53160a62d5ccc1325489f9d1c4ec27cf97197f416f206c585358c`.
Its MIT license is retained in `lazer/LICENSE`. Bundled Falcon and HEXL archives
retain their own notices. HEXL fetches CPU Features at commit
`32b49eb5e7809052a28422cfde2f2745fbb0eb76`.

The four upstream modifications are recorded in `../backend/lazer.patch`.
The generic upstream entry points outside this fixed adapter are unsupported.
Generated headers, binaries and extracted third-party build trees are ignored.
