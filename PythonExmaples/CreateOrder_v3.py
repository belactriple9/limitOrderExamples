# # Below is an example of placing a limit order on 1inch exchange
from eth_account.messages import encode_structured_data
from web3 import Web3
import requests
import time

# the time has come up update the code to v3, so lets start over and use the following breaking changes doc
"""
Order struct has changed as following:

struct Order {
    uint256 salt;
    address makerAsset;
    address takerAsset;
    address maker;
    address receiver;
    address allowedSender;  // equals to Zero address on public orders
    uint256 makingAmount;
    uint256 takingAmount;
-   // Was in v2
-   // bytes makerAssetData;
-   // bytes takerAssetData;
-   // bytes getMakingAmount; // this.staticcall(abi.encodePacked(bytes, swapTakerAmount)) => (swapMakerAmount)
-   // bytes getTakingAmount; // this.staticcall(abi.encodePacked(bytes, swapMakerAmount)) => (swapTakerAmount)
-   // bytes predicate;       // this.staticcall(bytes) => (bool)
-   // bytes permit;          // On first fill: permit.1.call(abi.encodePacked(permit.selector, permit.2))
-   // bytes interaction;
+   // Now in v3
+   uint256 offsets;
+   bytes interactions; // concat(makerAssetData, takerAssetData, getMakingAmount, getTakingAmount, predicate, permit, preIntercation, postInteraction)
}
where offset is bytes, where every 32's bytes represents offset of the n'ths interaction.

Eg: for [2, 4, 6] offsets:

(2n << 32n * 0n) + (4n << 32n * 1n) + (6n << 32n * 2n)
// 0x000000060000000400000002
See LimitOrderBuilder.joinStaticCalls() and LimitOrderBuilder.packInteractions() utils for help.

Order.interaction is now Order.postInteraction, as long as Order.preInteraction was added.
New arguments for fillOrder and fillOrderToWithPermit methods
function fillOrderToWithPermit(
    OrderLib.Order calldata order,
    bytes calldata signature,
+   bytes calldata interaction,
    uint256 makingAmount,
    uint256 takingAmount,
-   uint256 thresholdAmount,
+   uint256 skipPermitAndThresholdAmount,
    address target,
    bytes calldata permit
)
interaction is pre-interaction in fact.
skipPermit is just 255'th byte of skipPermitAndThresholdAmount, when rest of bytes is thresholdAmount
See fillLimitOrder(), fillOrderToWithPermit() and packSkipPermitAndThresholdAmount() utils methods and helpers.

Methods eq, lt, gt, nonceEquals no more have address arguments. Use arbitraryStaticCall instead in case if you need read value from different smartcontract.
"""

# Below is an example of placing a limit order on 1inch exchange
# same imports as above
# from eth_account.messages import encode_structured_data
# from web3 import Web3
# import requests
# import time
w3 = Web3(Web3.HTTPProvider("https://cloudflare-eth.com"))  # you can customize the RPC
wallet_key = "965e092fdfc08940d2bd05c7b5c7e1c51e283e92c7f52bbf1408973ae9a9acb7" # Your wallet private key
wallet_address = "0x2c9b2DBdbA8A9c969Ac24153f5C1c23CB0e63914" # Your wallet address
limit_order_contract = "0x1111111254EEB25477B68fb85Ed929f73A960582" # the limit order contract (now the same as the 1inch v5 router)
chain_id = 56 # the chain id of the network you are using ##didn't exist in the previoius version
ETHERSCAN_API_KEY = "yourapikeytoken" # Etherscan API key, this may not be required or should be changed if the ABIs are changed to literals or a different blockchain API is used like api.bscscan.com or api.polygonscan.com

#create the limit order contract instance
limit_order_contract_abi_response = requests.get(f"https://api.bscscan.com/api?module=contract&action=getabi&address={limit_order_contract}&apikey={ETHERSCAN_API_KEY}")
limit_order_contract_abi = limit_order_contract_abi_response.json()["result"]
limit_order_contract_instance = w3.eth.contract(address=limit_order_contract, abi=limit_order_contract_abi)

# wait 5 seconds to avoid rate limiting
time.sleep(5)

# get the token addresses for the tokens you want to trade
erc20_abi_response = requests.get(f"https://api.etherscan.io/api?module=contract&action=getabi&address=0x6b175474e89094c44da98b954eedeac495271d0f&apikey={ETHERSCAN_API_KEY}")
erc20_abi = erc20_abi_response.json()["result"]

#here is were we define parameters for the limit order
makerAddress = Web3.toChecksumAddress(wallet_address) # the address of the wallet that will be the maker of the order
takerAddress = Web3.toChecksumAddress("0x0000000000000000000000000000000000000000") # the address of the taker, if it's address(0) then it's a public order
makerAsset = Web3.toChecksumAddress("0x111111111117dC0aa78b770fA6A738034120C302") # the address of the token you want to sell
takerAsset = Web3.toChecksumAddress("0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56") # the address of the token you want to buy
makingAmount = 1000 # the amount of the token you want to sell in wei
takingAmount = 1000000000000000000000000000000000 # the amount of the token you want to buy in wei

makerAssetContract = w3.eth.contract(address=makerAsset, abi=erc20_abi)
takerAssetContract = w3.eth.contract(address=takerAsset, abi=erc20_abi)

# other order parameters
makerAssetData = '0x' #makerAssetContract.encodeABI(fn_name="transferFrom", args=[makerAddress, limit_order_contract, makerAmount])
takerAssetData = '0x' #takerAssetContract.encodeABI(fn_name="transferFrom", args=[takerAddress, limit_order_contract, takerAmount])
getMakingAmount = '0x'
getTakingAmount = '0x'
expiration = int(time.time()) + 60 * 60 * 24 # 1 days from now or a constant like 5444440000 some time in the future
nonce = 0 # the nonce of the order, used to be able to cancel all orders that have the same nonce by increasing the addresses' nonce
seriesNonceManagerContractAddress = w3.toChecksumAddress('0x58ce0e6ef670c9a05622f4188faa03a9e12ee2e4') # https://github.com/1inch/limit-order-protocol-utils/blob/fdbb559509eeb6e22e2697cccb22887d69617652/src/series-nonce-manager.const.ts
seriesNonceManagerABI_response = requests.get(f"https://api.bscscan.com/api?module=contract&action=getabi&address={seriesNonceManagerContractAddress}&apikey={ETHERSCAN_API_KEY}")
seriesNonceManagerABI = [{"inputs":[],"name":"AdvanceNonceFailed","type":"error"},{"anonymous":False,"inputs":[{"indexed":True,"internalType":"address","name":"maker","type":"address"},{"indexed":False,"internalType":"uint256","name":"series","type":"uint256"},{"indexed":False,"internalType":"uint256","name":"newNonce","type":"uint256"}],"name":"NonceIncreased","type":"event"},{"inputs":[{"internalType":"uint256","name":"series","type":"uint256"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"advanceNonce","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint8","name":"series","type":"uint8"}],"name":"increaseNonce","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"address","name":"","type":"address"}],"name":"nonce","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"series","type":"uint256"},{"internalType":"address","name":"makerAddress","type":"address"},{"internalType":"uint256","name":"makerNonce","type":"uint256"}],"name":"nonceEquals","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"time","type":"uint256"}],"name":"timestampBelow","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"timeNonceSeriesAccount","type":"uint256"}],"name":"timestampBelowAndNonceEquals","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]
seriesNonceManagerInstance = w3.eth.contract(address=seriesNonceManagerContractAddress, abi=seriesNonceManagerABI)
# in javascript, the packing is done like this
"""
    timestampBelowAndNonceEquals = (
        series: Series,
        timestamp: PredicateTimestamp,
        makerNonce: Nonce,
        makerAddress: string,
    ): string => {
        assertSeries(series);
        
        const predicateValue = BigInt(makerAddress)
            + (BigInt(series) << BigInt(160))
            + (BigInt(makerNonce) << BigInt(160 + 16))
            + (BigInt(timestamp) << BigInt(160 + 16 + 40));

        return this.facade.getContractCallData(
            SeriesNonceManagerMethods.timestampBelowAndNonceEquals,
            [ZX + predicateValue.toString(16)],
        );
    }
    """
series = 0 # 0 is limit order 1 is p2p order
nonceManagerCalldata = seriesNonceManagerInstance.encodeABI(fn_name="timestampBelow", args=[expiration])
predicate = limit_order_contract_instance.encodeABI(fn_name="arbitraryStaticCall", args=[seriesNonceManagerContractAddress, nonceManagerCalldata] )
permit = '0x' # this would be used to add an EIP 712 permit to the order
preInteraction = '0x' # this would be used to add a pre-interaction to the order
postInteraction = '0x' # this would be used to add a post-interaction to the order, for example unwrapping wETH to ETH
# print("Now we have all of the order data!")
# javascript for packing the interactions
"""

    const ZX = '0x'
    static packInteractions({
        makerAssetData = ZX,
        takerAssetData = ZX,
        getMakingAmount = ZX,
        getTakingAmount = ZX,
        predicate = ZX,
        permit = ZX,
        preInteraction = ZX,
        postInteraction = ZX,
    }: Partial<Interactions>): LimitOrderInteractions {
        const allInteractions = [
            makerAssetData,
            takerAssetData,
            getMakingAmount,
            getTakingAmount,
            predicate,
            permit,
            preInteraction,
            postInteraction,
        ];
    
        const { offsets, data: interactions } = this.joinStaticCalls(allInteractions);
        return { offsets, interactions };
    }

    static joinStaticCalls(data: string[]): { offsets: string, data: string } {
        const trimmed = data.map(trim0x);
    
        return {
            offsets: getOffsets(trimmed),
            data: ZX + trimmed.join(''),
        };
    }

    function getOffsets(data: string[]): string {
        const cumulativeSum = ((sum: bigint) => (value: bigint) => {
            sum += value;
            return sum;
        })
        (BigInt(0));

        return data
            .map((hex) => {
                if (hex.startsWith(ZX))
                    return BigInt(hex.length / 2 - 1);

                return BigInt(hex.length / 2);
            })
            .map(cumulativeSum)
            .reduce((bytesAccumularot, offset, index) => {
                return bytesAccumularot + (BigInt(offset) << ((UINT32_BITS * BigInt(index))));
            }, BigInt(0))
            .toString();
    }  
    function trim0x(hexString: string): string {
        if (hexString.startsWith('0x')) {
            return hexString.substring(2);
        }
        return hexString;
    }
"""

"""
where offset is bytes, where every 32's bytes represents offset of the n'ths interaction.

Eg: for [2, 4, 6] offsets:

(2n << 32n * 0n) + (4n << 32n * 1n) + (6n << 32n * 2n)
// 0x000000060000000400000002
"""
# to find the offsets we need to know the length of each thing in the interactions
# things in the interaction are makerAssetData, takerAssetData, getMakingAmount, getTakingAmount, predicate, permit, preIntercation, postInteraction

all_interactions = [makerAssetData, takerAssetData, getMakingAmount, getTakingAmount, predicate, permit, preInteraction, postInteraction]

def getOffsets(interactions):
    lenghtMap = []
    for interaction in interactions:
        if interaction[0:2] == "0x":
            lenghtMap.append(int(len(interaction)/2 - 1))
        else:
            lenghtMap.append(int(len(interaction)/2))
    cumulativeSum = 0
    bytesAccumularot = 0
    index = 0
    UINT32_BITS = 32
    # print(lenghtMap)
    for lenght in lenghtMap:    
        cumulativeSum += lenght
        # bytesAccumularot + (BigInt(offset) << ((exports.UINT32_BITS * BigInt(index))));
        # print(str(bytesAccumularot) + " + (" + str(cumulativeSum) + " << (" + str(UINT32_BITS) + " * " + str(index) + "))")
        bytesAccumularot += cumulativeSum << (UINT32_BITS * index)
        index += 1
    offsets = bytesAccumularot #hex(bytesAccumularot)
    return offsets

offsets = getOffsets(all_interactions)

def trim0x(hexString):
    if hexString[0:2] == '0x':
        return hexString[2:]
    return hexString

interactions = "0x"
for interaction in all_interactions:
    interactions = interactions + trim0x(interaction)


"""
    uint256 salt;
    address makerAsset;
    address takerAsset;
    address maker;
    address receiver;
    address allowedSender;  // equals to Zero address on public orders
    uint256 makingAmount;
    uint256 takingAmount;
    uint256 offsets;
    bytes interactions;
"""

# we'll just make salt the current time in seconds with no decimals
salt = int(time.time())

order_data = {
    "salt": (salt),
    "makerAsset": (makerAsset),
    "takerAsset": (takerAsset),
    "maker": (makerAddress),
    "receiver": (takerAddress),
    "allowedSender": ("0x0000000000000000000000000000000000000000"),
    "makingAmount": (makingAmount),
    "takingAmount": (takingAmount),
    "offsets": (offsets),
    "interactions": (interactions)
}

order_types = [
    {"name": "salt", "type": "uint256"},
    {"name": "makerAsset", "type": "address"},
    {"name": "takerAsset", "type": "address"},
    {"name": "maker", "type": "address"},
    {"name": "receiver", "type": "address"},
    {"name": "allowedSender", "type": "address"},
    {"name": "makingAmount", "type": "uint256"},
    {"name": "takingAmount", "type": "uint256"},
    {"name": "offsets", "type": "uint256"},
    {"name": "interactions", "type": "bytes"},
]


# this function will fix the order_data to be a typed object instead of only strings
def fix_data_types(data, types):
    """
    Order data values are all strings as this is what the API expects. This function fixes their types for
    encoding purposes.
    """
    fixed_data = {}
    for dictionary in types:
        if "bytes" in dictionary["type"]:
            fixed_data[dictionary["name"]] = (Web3.toBytes(hexstr=data[dictionary["name"]]))
        elif "int" in dictionary["type"]:
            fixed_data[dictionary["name"]] = int(data[dictionary["name"]])
        else: # address
            fixed_data[dictionary["name"]] = data[dictionary["name"]]
    return fixed_data

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
    "domain": {
        "name": "1inch Aggregation Router",
        "version": "5",
        "chainId": chain_id,
        "verifyingContract": "0x1111111254eeb25477b68fb85ed929f73a960582",
    },
    "message": fix_data_types(order_data, order_types),
}

# print(fix_data_types(order_data, order_types))
# print()
# print()

# this is fine
encoded_message = encode_structured_data(eip712_data)
# print(encoded_message)

# this is the problematic portion##############################################
# in short this doesn't work when using an m1 mac for some reason
# the stuff that should work if I install the thing below
# if you're having issues, see this https://github.com/ethereum/eth-account/issues/90
# pip install eth-account==0.6.1
signed_message = w3.eth.account.sign_message(encoded_message, wallet_key)
# this is the limit order that will be broadcast to the limit order API
# account = w3.eth.account.privateKeyToAccount(wallet_key)
# signed_boi = w3.eth.sign_typed_data(account.address, eip712_data)
# print(signed_boi)
# signed_message = account.signTypedData(eip712_data)
# print(signed_message)
# this is the problematic portion##############################################

# make sure everything in the order_data is a string except for salt
for key in order_data:
    if key != "salt":
        order_data[key] = str(order_data[key])


limit_order = {
    "orderHash": signed_message.messageHash.hex(),
    "signature": signed_message.signature.hex(),
    "data": order_data,
}

# print(limit_order)

"""
in javascript these are both valid


    let fetchPromise = await fetch("https://limit-orders.1inch.io/v3.0/56/limit-order", {
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

url = "https://limit-orders.1inch.io/v3.0/56/limit-order" # 56 is for BNB (formerly BSC)

headers = {'Content-Type': 'application/json'}

stringified = json.dumps(limit_order)

print(stringified)

# send the request
response = requests.post(url, data=stringified, headers=headers)
print(response.text)
