#!/usr/bin/python3

from algosdk import mnemonic
from algosdk import account
from web3 import Web3

# mnemonic to generate the public key for the exchange server
eth_mnemonic = "midnight game play tail blossom cereal jacket cruel okay slim verify harbor"
algo_mnemonic = "avocado coil energy gallery health brief crime peanut coyote brother coach bullet december limit oblige answer town bar neck provide ivory cousin custom abstract demise"


def eth():
    try:

        w3 = Web3()
        w3.eth.account.enable_unaudited_hdwallet_features()
        acct = w3.eth.account.from_mnemonic(eth_mnemonic)
        return acct._address

    except Exception as e:
        print("Couldn't get Ethereum server")
        print(e)


def algo():
    try:

        algo_pk = mnemonic.to_public_key(algo_mnemonic)

        return algo_pk

    except Exception as e:
        print("Couldn't get Algorand server pk")
