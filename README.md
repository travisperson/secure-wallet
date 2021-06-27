# Secure Wallet

[![license](https://img.shields.io/github/license/travisperson/secure-wallet.svg)](LICENSE)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

Secure Wallet aims to improve upon the authenication and authorization model of the `lotus-wallet` tool by proving more control of user
permissions and authorization to different wallets.

## Background

Lotus provides access to two different kinds of wallet services. A local wallet, which stores wallet secrets in the local lotus repository
and a remote wallet service, which lotus can be configured to use. Lotus provides a remote service through the `lotus-wallet` tool. Both
the local wallet and the `lotus-wallet` tool have an all or nothing approach to authorization and authenication. A user either has access,
or they do not have access. With access a user can perform all operations, `WalletNew`, `WalletHas`, `WalletList`, `WalletExport`, `WalletImport`, `WalletSign` and `WalletDelete` for all wallet address inside of the keystore.

Secure Wallet tries to improve upon the authenication and authorization model by providing a more fined grained list of permissions on the
lotus api. The methods `WalletHas`, `WalletList` are assigned under the permission `Read`. Methods `WalletNew`, `WalletImport` are assigned
`Write`, `WalletSign` the `Sign` permission, leaving `WalletExport`, `WalletDelete` to the `Admin` permission. The client to the Secure
Wallet service is authenicated and authorized with a jwt take which contains a list of permissions, as well a list of authorized wallets.

| Permission  | Methods                     |
| :---        | :---                        |
| Read        | WalletHas, WalletList       |
| Write       | WalletNew, WalletImport     |
| Sign        | WalletSign                  |
| Admin       | WalletExport, WalletDelete  |

The method under `Read` and `Sign` are the only implemented methods on the wallet service. This because the wallet service primarly is
designed to be used as a way to secure the private data of wallets. The Secure Wallet backend wraps around the full permissioned api of
the `lotus-wallet` tool.

## Build

```
$ go build -o secure-wallet ./cmd/secure-wallet
```

## Usage

Secure Wallet depends on [lotus-wallet](https://github.com/filecoin-project/lotus/tree/master/cmd/lotus-wallet) for a backing wallet store
and [lotus-shed](https://github.com/filecoin-project/lotus-tree/master/cmd/lotus-shed) for generating jwt secrets.

The complete deployment of Secure Wallet envoles `lotus`, `lotus-wallet`, a Secure Wallet backend and a Secure Wallet frontend.

First we will run `lotus-wallet` and create some wallet address, take note of these addresses. We will refer to them as `<addr1>` through
`<addr4>`.

```bash
$ lotus-wallet run
---
$ # see secure-wallet frontend --help
$ secure-wallet frontend client --lotus-wallet-api http://localhost:1777 new secp256k1
<addr1>
$ secure-wallet frontend client --lotus-wallet-api http://localhost:1777 new secp256k1
<addr2>
$ secure-wallet frontend client --lotus-wallet-api http://localhost:1777 new secp256k1
<addr3>
$ secure-wallet frontend client --lotus-wallet-api http://localhost:1777 new secp256k1
<addr4>
```

We will now setup the backend service by creating a jwt secret and a few tokens to test with

```bash
$ lotus-shed jwt new backend
$ secure-wallet backend token create --global-read | tr -d '\n' > jwt-global-read.token
$ secure-wallet backend token create --read --sign <addr1> <addr2> | tr -d '\n' > jwt.token
$ # see secure-wallet backend --help
$ secure-wallet backend run
---
$ secure-wallet backend client --jwt-token-path ./jwt-global-read.token list
<addr1>
<addr2>
<addr3>
<addr4>
$ secure-wallet backend client --jwt-token-path ./jwt.token list
<addr1>
<addr2>
$ secure-wallet backend client --jwt-token-path ./jwt.token sign <addr1> <hex>
<blob>
$ secure-wallet backend client --jwt-token-path ./jwt.token sign <addr3> <hex>
error: signer address does not exist
```

These tokens can be used directoy with lotus by configuring the remote wallet and pointing to the Secure Wallet backend. However, there is an
added benefit to running the Secure Wallet frontend. First, to use the lotus remote wallet configuration the jwt token needs to be stored in
the configuration file. This introduces challenges when it comes to deployments. The Secure Wallet frontend loads the token from a file instead.
It also will periodically reload this token from disk enable deployments to easily rotate out jwt tokens without having to restart the service.

Additional work is planned to take advantage of expiring tokens, and integration with Hashicorp Vault for token rotations.

## Contributing

Feel free to dive in! [Open an issue](https://github.com/travisperson/secure-wallet/issues/new) or submit PRs.

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT](LICENSE)
