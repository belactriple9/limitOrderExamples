# # Below is an example of placing a limit order on 1inch, please note this was built with web3py 6.15.1, eth-account 0.11.0
from eth_account.messages import encode_typed_data
from web3 import Web3
import requests
import time

# Limit order v4.0 has changed some parts of the limit order structure
"""
Order struct has changed as following:

struct Order {
    uint256 salt;
    address makerAsset;
    address takerAsset;
    address maker;
    address receiver;

    uint256 makingAmount;
    uint256 takingAmount;
-   // in v3 the following fields were used
-   // uint256 offsets;
-   // bytes interactions;
-   // address allowedSender;  // packed into the makerTraits
+   // now in v4
+   uint256 makerTraits
+   bytes extenion // concat(offsets, interactions) where interactions = concat(makerAssetSuffix, takerAssetSuffix, makingAmountData, takingAmountData, predicate, permit, preInteraction, postInteraction)
}
Methods eq, lt, gt, nonceEquals do not address arguments. Use arbitraryStaticCall instead in case if you need read value from different smartcontract.
"""


# first define the helper functions
def getOffsets(interactions):
    lenghtMap = []
    for interaction in interactions:
        if interaction[0:2] == "0x":
            lenghtMap.append(int(len(interaction)/2 - 1))
        else:
            lenghtMap.append(int(len(interaction)/2))
    cumulativeSum = 0
    bytesAccumulator = 0
    index = 0
    UINT32_BITS = 32
    for lenght in lenghtMap:    
        cumulativeSum += lenght
        bytesAccumulator += cumulativeSum << (UINT32_BITS * index)
        index += 1
    offsets = bytesAccumulator
    return offsets

def trim0x(hexString):
    if hexString[0:2] == '0x':
        return hexString[2:]
    return hexString

# this function will fix the order_data to be a typed object instead of only strings
def fix_data_types(data, types):
    """
    Order data values are all strings as this is what the API expects. This function fixes their types for
    encoding purposes.
    """
    fixed_data = {}
    for dictionary in types:
        if "bytes" in dictionary["type"]:
            fixed_data[dictionary["name"]] = (Web3.to_bytes(hexstr=data[dictionary["name"]]))
        elif "int" in dictionary["type"]:
            fixed_data[dictionary["name"]] = lambda x: int(x, 16) if isinstance(x, str) and all(c in '0123456789abcdefABCDEF' for c in x.strip('0x')) else (0 if x == '0x' else int(x))
        else: # address
            fixed_data[dictionary["name"]] = data[dictionary["name"]]
    return fixed_data

_NO_PARTIAL_FILLS_FLAG = 255
_ALLOW_MULTIPLE_FILLS_FLAG = 254
_NEED_PREINTERACTION_FLAG = 252
_NEED_POSTINTERACTION_FLAG = 251
_NEED_EPOCH_CHECK_FLAG = 250
_HAS_EXTENSION_FLAG = 249
_USE_PERMIT2_FLAG = 248
_UNWRAP_WETH_FLAG = 247


def build_makerTraits(allowedSender, shouldCheckEpoch, usePermit2, unwrapWeth, hasExtension, hasPreInteraction, hasPostInteraction, expiry, nonce, series):
    # require expiry less than 40 bits
    # if expiry < 2**40 - 1:
    #     return # expiry must be less than 40 bits
    # if nonce < 2**40 - 1:
    #     return  # nonce must be less than 40 bits
    # if series < 2**40 - 1:
    #     return 
    tempPredicate = (series << 160 | nonce << 120 | expiry << 80 | int(allowedSender, 16) & ((1 << 80) - 1)) # allowedSender should be a hex string, so converting to an int is valid. 
    if unwrapWeth: # then set the _UNWRAP_WETH_FLAG bit to 1
        tempPredicate = tempPredicate | (1 << _UNWRAP_WETH_FLAG)
    # MUST BE SET
    # if allowMultipleFills: 
    tempPredicate = tempPredicate | (1 << _ALLOW_MULTIPLE_FILLS_FLAG)
    # MUST BE 0
    #if allowPartialFill:
    #    tempPredicate = tempPredicate | (1 << _NO_PARTIAL_FILLS_FLAG)
    if shouldCheckEpoch:
        tempPredicate = tempPredicate | (1 << _NEED_EPOCH_CHECK_FLAG)
    if usePermit2:
        tempPredicate = tempPredicate | (1 << _USE_PERMIT2_FLAG)
    if hasExtension:
        tempPredicate = tempPredicate | (1 << _HAS_EXTENSION_FLAG)
    if hasPreInteraction:
        tempPredicate = tempPredicate | (1 << _NEED_PREINTERACTION_FLAG)
    if hasPostInteraction:
        tempPredicate = tempPredicate | (1 << _NEED_POSTINTERACTION_FLAG)
    # finally, pad the predicate to 32 bytes with 0's on the left and attach a '0x' to the front
    return '0x' + tempPredicate.to_bytes(32, 'big').hex()

def build_extension(interactions, offsets):
    if interactions == "0x":
        return "0x"
    return  '0x' + offsets.to_bytes(32, 'big').hex() + trim0x(interactions)

# Below is an example of placing a limit order on 1inch exchange
# same imports as above
# from eth_account.messages import encode_structured_data
# from web3 import Web3
# import requests
# import time
w3 = Web3(Web3.HTTPProvider("https://cloudflare-eth.com"))  # you can customize the RPC
wallet_key = "965e092fdfc08940d2bd05c7b5c7e1c51e283e92c7f52bbf1408973ae9a9acb7" # Your wallet private key
wallet_address = "0x2c9b2DBdbA8A9c969Ac24153f5C1c23CB0e63914" # Your wallet address
limit_order_contract = "0x111111125421cA6dc452d289314280a0f8842A65" # the limit order contract (same as v6 router, this address is only different on zksync)
chain_id = 1 # the chain id of the network you are using ##didn't exist in the previoius version
ETHERSCAN_API_KEY = "yourapikeytoken" # Etherscan API key, this may not be required or should be changed if the ABIs are changed to literals or a different blockchain API is used like api.bscscan.com or api.polygonscan.com


#create the limit order contract instance
limit_order_contract_abi_response = requests.get(f"https://api.etherscan.io/api?module=contract&action=getabi&address={limit_order_contract}&apikey={ETHERSCAN_API_KEY}")
limit_order_contract_abi = limit_order_contract_abi_response.json()["result"]
limit_order_contract_instance = w3.eth.contract(address=limit_order_contract, abi=limit_order_contract_abi)

# wait 5 seconds to avoid rate limiting
time.sleep(5)

# get the token addresses for the tokens you want to trade
erc20_abi_response = requests.get(f"https://api.etherscan.io/api?module=contract&action=getabi&address=0x6b175474e89094c44da98b954eedeac495271d0f&apikey={ETHERSCAN_API_KEY}")
erc20_abi = erc20_abi_response.json()["result"]

#here is were we define parameters for the limit order
makerAddress = Web3.to_checksum_address(wallet_address) # the address of the wallet that will be the maker of the order
nullAddress = Web3.to_checksum_address("0x0000000000000000000000000000000000000000") # the address of the taker, if it's address(0) then it's a public order
makerAsset = Web3.to_checksum_address("0xc5102fe9359fd9a28f877a67e36b0f050d81a3cc") # the address of the token you want to sell
takerAsset = Web3.to_checksum_address("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") # the address of the token you want to buy
makingAmount = 1000000000000000000 # the amount of the token you want to sell in wei
takingAmount = 1000000000 # the amount of the token you want to buy in wei

makerAssetContract = w3.eth.contract(address=makerAsset, abi=erc20_abi)
takerAssetContract = w3.eth.contract(address=takerAsset, abi=erc20_abi)

# other order parameters
makerAssetSuffix = '0x'
takerAssetSuffix = '0x'
makingAmountData = '0x'
takingAmountData = '0x'
permit = '0x'                                       # this would be used to add an EIP 712 permit to the order
preInteraction = '0x'                               # Used to interactively handle maker assets before the order is executed, for example unwrapping aave aTokens
postInteraction = '0x'                              # this would be used to add a post-interaction to the order, for example sending funds to a bridge after the order is executed
predicate = '0x'                                    # 0x means no predicate, so the order doesn't not expire and must be explicitly canceled

# we can build the extension
all_interactions = [makerAssetSuffix, takerAssetSuffix, makingAmountData, takingAmountData, predicate, permit, preInteraction, postInteraction]
offsets = getOffsets(all_interactions)

interactions = "0x"
for interaction in all_interactions:
    interactions = interactions + trim0x(interaction)


# predicate parameters and construction, because we have an extension we must toggle the flag
expiration = int(time.time()) + 60                  # 1 minute from now in this example
nonce = 0                                           # the nonce of the order, used to be able to cancel all orders that have the same nonce by increasing the addresses' nonce
series = 0                                          # series of the order, used to cancel all orders with the same series by increasing the nonce on the given series. 0 = normal order, 1 p2p order (deprecated), ? = fusion order
has_extension = interactions != "0x"                # if the interactions are not empty, then the order has an extension
makerTraits = build_makerTraits(nullAddress, False, False, False, has_extension, False, False, expiration, nonce, series)

extension = build_extension(interactions, offsets)
# in javascript
#  salt = BigInt(keccak256(extension)) & ((1n << 160n) - 1n); // Use 160 bit of extension hash
# salt should be a 160 bits of the keccak hash of the extension
if not has_extension:
    current_time = int(time.time())  # Convert time to an integer to avoid floating-point precision issues
    salt_bytes = current_time.to_bytes(32, 'big')  # Convert the integer timestamp to bytes
    salt = int.from_bytes(w3.keccak(salt_bytes), 'big') & ((1 << 160) - 1)
else: 
    salt = int.from_bytes(w3.keccak(hexstr=extension), 'big') & ((1 << 160) - 1)

order_data = {
    "salt": (salt),
    "makerAsset": (makerAsset),
    "takerAsset": (takerAsset),
    "maker": (makerAddress),
    "receiver": (nullAddress),
    "makingAmount": (makingAmount),
    "takingAmount": (takingAmount),
    "makerTraits": (makerTraits),
    "extension": (extension)
}


order_types = order_types = [
    {"name": "salt", "type": "uint256"},
    {"name": "maker", "type": "address"},
    {"name": "receiver", "type": "address"},
    {"name": "makerAsset", "type": "address"},
    {"name": "takerAsset", "type": "address"},
    {"name": "makingAmount", "type": "uint256"},
    {"name": "takingAmount", "type": "uint256"},
    {"name": "makerTraits", "type": "uint256"},
]

domain_data = {
    "name": "1inch Aggregation Router",
    "version":  "6",
    "chainId": chain_id, # 1 for ethereum network. 
    "verifyingContract": limit_order_contract,
}

fixed_data = fix_data_types(order_data, order_types)

eip712_data = {
    "primaryType": "Order",
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Order": order_types
    },
    "domain": domain_data,
    "message": fixed_data
}

message_types = {
    "Order": order_types
}

encoded_message = encode_typed_data(domain_data, message_types, order_data ) #new method, but doesn't work, tests fail
signed_message = w3.eth.account.sign_message(encoded_message, wallet_key)

# make sure everything in the order_data is a string for the API
for key in order_data:
    order_data[key] = str(order_data[key])

limit_order = {
    "orderHash": signed_message.messageHash.hex(),
    "signature": signed_message.signature.hex(),
    "data": order_data,
}

# print(limit_order)

"""
in javascript these are both valid


    let fetchPromise = await fetch("https://limit-orders.1inch.io/v4.0/1/limit-order", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    });
"""

# this is the limit order that will be broadcast to the limit order API

import requests
import json

url = "https://limit-orders.1inch.io/v4.0/1/limit-order" # 1 is for Ethereum network

headers = {'Content-Type': 'application/json'}

stringified = json.dumps(limit_order)

print(stringified)

# send the request
response = requests.post(url, data=stringified, headers=headers)
print(response.text)
