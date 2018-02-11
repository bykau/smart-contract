"""Mutliparty lottery smart contract on Bitcoin

This module demonstrates a prototype implementation of multiparty lottery
where three parties randomly choose a winner. It consists of the two phases:
openning: where parties publish hashes of their random secrets and gambling:
where the actual lottery happen based on the length of those secret strings. 
The current code was tested on Bitcoin testnet and all transactions can be 
seen on a block explorer (see https://live.blockcypher.com links). 

The module is based on the python-bitcoinlib. To publish raw transaction BlockCypher
was used.

References:
    * https://curiosity-driven.org/bitcoin-contracts
    * https://eprint.iacr.org/2013/784.pdf
    * https://github.com/petertodd/python-bitcoinlib
    * https://live.blockcypher.com/btc-testnet/pushtx/
    
Todo:
    * Depoist tx unlock condition should be (SigA & secretA) || (SigA & SigB)
    * Test fine_tx method
"""
from bitcoin import SelectParams
from bitcoin.core import x, b2x, lx, COIN, COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction, Hash160
from bitcoin.core.script import CScript, OP_DUP, OP_DROP, OP_HASH160, OP_EQUAL, OP_EQUALVERIFY, OP_CHECKSIG, \
    SignatureHash, SIGHASH_ALL, OP_SHA256, OP_SWAP, OP_BOOLOR, OP_BOOLAND, OP_0, OP_SIZE, OP_TUCK, OP_WITHIN, \
    OP_VERIFY, OP_ROT, OP_ADD, OP_SUB, OP_2, OP_GREATERTHAN, OP_IF, OP_3, OP_ENDIF, OP_ROLL
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress
import hashlib

SelectParams("testnet")


def open_tx(funding_tx, vout, seckey, amount, secret, pubkey_other):
    script = CScript([OP_SHA256, hashlib.sha256(secret).digest(), OP_EQUAL, OP_SWAP, seckey.pub, OP_CHECKSIG, OP_BOOLOR,
                      OP_SWAP, pubkey_other, OP_CHECKSIG, OP_BOOLAND])
    txin = CMutableTxIn(COutPoint(lx(funding_tx), vout))
    txin_scriptPubKey = CScript([OP_DUP, OP_HASH160, Hash160(seckey.pub), OP_EQUALVERIFY, OP_CHECKSIG])
    txout = CMutableTxOut(amount * COIN, script)
    tx = CMutableTransaction([txin], [txout])
    sighash = SignatureHash(txin_scriptPubKey, tx, 0, SIGHASH_ALL)
    sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])
    txin.scriptSig = CScript([sig, seckey.pub])
    VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,))
    return b2x(tx.serialize())


def deposit_tx(funding_tx, vout, seckey_a, seckey_b, amount, secret):
    txin = CMutableTxIn(COutPoint(lx(funding_tx), vout))
    # TODO: there is a bug in the script: it should be either sigA+sigB or sigA+secret
    txin_script = CScript([OP_SHA256,
                    hashlib.sha256(secret).digest(),
                    OP_EQUAL,
                    OP_SWAP,
                    seckey_a.pub,
                    OP_CHECKSIG,
                    OP_BOOLOR,
                    OP_SWAP,
                    seckey_b.pub,
                    OP_CHECKSIG,
                    OP_BOOLAND])
    txout = CMutableTxOut(amount * COIN, P2PKHBitcoinAddress.from_pubkey(seckey_a.pub).to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout])
    sighash = SignatureHash(txin_script, tx, 0, SIGHASH_ALL)
    sigA= seckey_a.sign(sighash) + bytes([SIGHASH_ALL])
    sigB = seckey_b.sign(sighash) + bytes([SIGHASH_ALL])
    txin.scriptSig = CScript([sigB, sigA, secret_a])
    VerifyScript(txin.scriptSig, txin_script, tx, 0, (SCRIPT_VERIFY_P2SH,))
    return b2x(tx.serialize())


def fine_tx(funding_tx, vout, seckey, amount, secret, other_pub):
    # TODO: test fine_tx
    txin = CMutableTxIn(COutPoint(lx(funding_tx), vout))
    txin_script = CScript([OP_SHA256,
                    hashlib.sha256(secret).digest(),
                    OP_EQUAL,
                    OP_SWAP,
                    other_pub,
                    OP_CHECKSIG,
                    OP_BOOLOR,
                    OP_SWAP,
                    seckey.pub,
                    OP_CHECKSIG,
                    OP_BOOLAND])
    txout = CMutableTxOut(amount * COIN, P2PKHBitcoinAddress.from_pubkey(seckey.pub).to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout], 10)
    sighash = SignatureHash(txin_script, tx, 0, SIGHASH_ALL)
    sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])
    txin.scriptSig = CScript([sig, OP_0])
    return b2x(tx.serialize())


def gamble_tx(funding_tx, vout, seckey_fund, amount, seckey_a, seckey_b, seckey_c, secret_a, secret_b, secret_c):
    script = CScript([OP_SIZE, OP_TUCK, x("20"), x("23"), OP_WITHIN, OP_VERIFY, OP_SHA256, hashlib.sha256(secret_a).digest(),
                      OP_EQUALVERIFY, OP_SWAP, OP_SIZE, OP_TUCK, x("20"), x("23"), OP_WITHIN, OP_VERIFY, OP_SHA256,
                      hashlib.sha256(secret_b).digest(), OP_EQUALVERIFY, OP_ROT, OP_SIZE, OP_TUCK, x("20"), x("23"),
                      OP_WITHIN, OP_VERIFY, OP_SHA256, hashlib.sha256(secret_c).digest(), OP_EQUALVERIFY, OP_ADD,
                      OP_ADD, x("60"), OP_SUB, OP_DUP, OP_2, OP_GREATERTHAN, OP_IF, OP_3, OP_SUB, OP_ENDIF, OP_DUP, OP_2,
                      OP_GREATERTHAN, OP_IF, OP_3, OP_SUB, OP_ENDIF, seckey_a.pub, seckey_b.pub, seckey_c.pub, OP_3, OP_ROLL,
                      OP_ROLL, OP_3, OP_ROLL, OP_SWAP, OP_3, OP_ROLL, OP_DROP, OP_2, OP_ROLL, OP_DROP, OP_CHECKSIG])
    txin = CMutableTxIn(COutPoint(lx(funding_tx), vout))
    txin_scriptPubKey = CScript([OP_DUP, OP_HASH160, Hash160(seckey_fund.pub), OP_EQUALVERIFY, OP_CHECKSIG])
    txout = CMutableTxOut(amount * COIN, script)
    tx = CMutableTransaction([txin], [txout])
    sighash = SignatureHash(txin_scriptPubKey, tx, 0, SIGHASH_ALL)
    sig = seckey_fund.sign(sighash) + bytes([SIGHASH_ALL])
    txin.scriptSig = CScript([sig, seckey_fund.pub])
    VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,))
    txin.scriptSig = CScript([sig, seckey_fund.pub])
    return b2x(tx.serialize())


def claim_tx(funding_tx, vout, amount, seckey, secret_a, secret_b, secret_c):
    script = CScript([OP_SIZE, OP_TUCK, x("20"), x("23"), OP_WITHIN, OP_VERIFY, OP_SHA256, hashlib.sha256(secret_a).digest(),
                      OP_EQUALVERIFY, OP_SWAP, OP_SIZE, OP_TUCK, x("20"), x("23"), OP_WITHIN, OP_VERIFY, OP_SHA256,
                      hashlib.sha256(secret_b).digest(), OP_EQUALVERIFY, OP_ROT, OP_SIZE, OP_TUCK, x("20"), x("23"),
                      OP_WITHIN, OP_VERIFY, OP_SHA256, hashlib.sha256(secret_c).digest(), OP_EQUALVERIFY, OP_ADD,
                      OP_ADD, x("60"), OP_SUB, OP_DUP, OP_2, OP_GREATERTHAN, OP_IF, OP_3, OP_SUB, OP_ENDIF, OP_DUP, OP_2,
                      OP_GREATERTHAN, OP_IF, OP_3, OP_SUB, OP_ENDIF, seckey_a.pub, seckey_b.pub, seckey_c.pub, OP_3, OP_ROLL,
                      OP_ROLL, OP_3, OP_ROLL, OP_SWAP, OP_3, OP_ROLL, OP_DROP, OP_2, OP_ROLL, OP_DROP, OP_CHECKSIG])
    txin = CMutableTxIn(COutPoint(lx(funding_tx), vout))
    txout = CMutableTxOut(amount * COIN, P2PKHBitcoinAddress.from_pubkey(seckey.pub).to_scriptPubKey())
    tx = CMutableTransaction([txin], [txout])
    sighash = SignatureHash(script, tx, 0, SIGHASH_ALL)
    sig = seckey_c.sign(sighash) + bytes([SIGHASH_ALL])
    txin.scriptSig = CScript([sig, secret_c, secret_b, secret_a])
    VerifyScript(txin.scriptSig, script, tx, 0, (SCRIPT_VERIFY_P2SH,))
    return b2x(tx.serialize())


if __name__ == "__main__":
    seckey_a = CBitcoinSecret.from_secret_bytes(hashlib.sha256(b'-5E!9V7F?jhcvU"L').digest())
    secret_a = x("2c2c01dc829177da4a14551d2fc96a9db00c6501edfa12f22cd9cefd335c338e")
    print("PubkeyA: {}".format(P2PKHBitcoinAddress.from_pubkey(seckey_a.pub)))
    print("secretA: {}".format(b2x(seckey_a)))
    print("sha256(secretA): {}".format(b2x(hashlib.sha256(secret_a).digest())))
    print()

    seckey_b = CBitcoinSecret.from_secret_bytes(hashlib.sha256(b'VBwF^NfN8uxS8(MGp').digest())
    secret_b = x("1b1b01dc829177da4a14551d2fc96a9db00c6501edfa12f22cd9cefd335c227f")
    print("PubkeyB: {}".format(P2PKHBitcoinAddress.from_pubkey(seckey_b.pub)))
    print("secretB: {}".format(b2x(seckey_b)))
    print("sha256(secretB): {}".format(b2x(hashlib.sha256(secret_b).digest())))
    print()

    seckey_c = CBitcoinSecret.from_secret_bytes(hashlib.sha256(b'i`f`,&,!8Rhs"GPd').digest())
    secret_c = x("ca42095840735e89283fec298e62ac2ddea9b5f34a8cbb7097ad965b87568123")
    print("PubkeyC: {}".format(P2PKHBitcoinAddress.from_pubkey(seckey_c.pub)))
    print("secretC: {}".format(b2x(seckey_c)))
    print("sha256(secretC): {}".format(b2x(hashlib.sha256(secret_c).digest())))
    print()

    seckey_fund = CBitcoinSecret.from_secret_bytes(hashlib.sha256(b'c+C){-nHtH!8>(7').digest())
    print("PubkeyFund: {}".format(P2PKHBitcoinAddress.from_pubkey(seckey_fund.pub)))
    print()

    print("open_tx_a: {}".format(open_tx("fc26d8f92557354c33f2d8efe6791bad9d0e2117b4c539f31e8de3880f6f042e",
                                         0,
                                         seckey_a,
                                         0.00499,
                                         secret_a,
                                         seckey_b.pub)
                                 )
          )
    print("https://live.blockcypher.com/btc-testnet/tx/2cf018eee2ed79d606e44543296b64881a8789205e50ab564c615e1a5a3363fb/")
    print()

    print("open_tx_b: {}".format(open_tx("18bdb44f10484638dea245c919bbc760b13c1240a17c782c3a573c6a182eafca",
                                         0,
                                         seckey_b,
                                         0.00499,
                                         secret_b,
                                         seckey_c.pub)
                                 )
          )
    print("https://live.blockcypher.com/btc-testnet/tx/611aa4e74d8dda1a726b76f590e91e3920740350ac6a616d649f930dd378e39f/")
    print()

    print("open_tx_c: {}".format(open_tx("4692021f2dc3f93c3928a9920b5a3285417486c8a9d523719a0c8bf3f7e1282e",
                                         0,
                                         seckey_c,
                                         0.00499,
                                         secret_c,
                                         seckey_a.pub)
                                 )
          )
    print("https://live.blockcypher.com/btc-testnet/tx/79151043c0f3942e38818ffb66c2d09fd82045419dc86a5b276685c9de71dcd2/")
    print()

    print("gamble_tx: {}".format(gamble_tx("aa63500ae45e3e3addb672c23e2be2c3d0318aad44e5622a8ce81c6f85535371",
                     0,
                                           seckey_fund,
                                           0.00499,
                                           seckey_a,
                                           seckey_b,
                                           seckey_c,
                                           secret_a,
                                           secret_b,
                                           secret_c)
                                 )
          )
    print("https://live.blockcypher.com/btc-testnet/tx/ccb44ea89bb0b1d55e1fa37b7a126ad5ba78c0b47662b68390fe2f69092587d5/")
    print()

    print("deposit_tx_a: {}".format(deposit_tx("2cf018eee2ed79d606e44543296b64881a8789205e50ab564c615e1a5a3363fb",
                                               0,
                                               seckey_a,
                                               seckey_b,
                                               0.00497,
                                               secret_a)
                                    )
          )

    print("https://live.blockcypher.com/btc-testnet/tx/e5c201ad8146d6d89f631867ab5e19421a25d3d973b399732e4d8d6881b36b86/")
    print()

    print("deposit_tx_b: {}".format(deposit_tx("611aa4e74d8dda1a726b76f590e91e3920740350ac6a616d649f930dd378e39f",
                                               0,
                                               seckey_b,
                                               seckey_c,
                                               0.00497,
                                               secret_b)
                                    )
          )
    print("https://live.blockcypher.com/btc-testnet/tx/ddc5dde58f2d4b60b4d508d6f387430558eb7b1a2ad385749099b784b4fb5fa6/")
    print()

    print("deposit_tx_c: {}".format(deposit_tx("79151043c0f3942e38818ffb66c2d09fd82045419dc86a5b276685c9de71dcd2",
                                               0,
                                               seckey_c,
                                               seckey_a,
                                               0.00497,
                                               secret_c)
                                    )
          )
    print("https://live.blockcypher.com/btc-testnet/tx/726f985d1d047cc805b0a34bfe1512346939e4154231ba09a2c1de87e7207a49/")
    print()

    print("claim_tx_c: {}".format(claim_tx("ccb44ea89bb0b1d55e1fa37b7a126ad5ba78c0b47662b68390fe2f69092587d5",
                                            0,
                                            0.00497,
                                            seckey_c,
                                            secret_a,
                                            secret_b,
                                            secret_c)
                                  )
          )
    print("https://live.blockcypher.com/btc-testnet/tx/239ffd23f912b0587263e11139989064c5146041635f981dcbf889fb3266600d/")
