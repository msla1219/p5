#!/usr/bin/python3

from algosdk import mnemonic
from algosdk import account
from web3 import Web3


def get_eth_key(eth_mnemonic):
    try:

        w3 = Web3()
        w3.eth.account.enable_unaudited_hdwallet_features()
        acct = w3.eth.account.from_mnemonic(eth_mnemonic)
        eth_pk = acct._address

        return eth_pk

    except Exception as e:
        print("Couldn't get Ethereum server pk: ", eth_pk)
        print(e)


def get_algo_key(algo_mnemonic):
    try:

        algo_pk = mnemonic.to_public_key(algo_mnemonic)

        return algo_pk

    except Exception as e:
        print("Couldn't get Ethereum server pk: ", algo_pk)
