// add "type": "module" to your package.json to run this with node or name the file with extension .mjs to prevent writing existing .js files

import { LimitOrder, MakerTraits, Address } from "@1inch/limit-order-sdk"
import { Wallet } from 'ethers'
import { Api, getLimitOrderV4Domain } from "@1inch/limit-order-sdk"
import { AxiosProviderConnector } from '@1inch/limit-order-sdk/axios';
import 'dotenv/config';

// ERC20 Token standard ABI for the approve function
const erc20AbiFragment = [
    "function approve(address spender, uint256 amount) external returns (bool)"
];

(async () => {

    // it is a well-known test private key, do not use it in production
    const privKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; //String(process.env.PRIVATE_KEY);
    const chainId = 1;

    const maker = new Wallet(privKey)
    const expiresIn = 120n // 2m
    const expiration = BigInt(Math.floor(Date.now() / 1000)) + expiresIn

    //Orders must call the approve function prior to being submitted
    // Initialize ethers provider
    const provider = new JsonRpcProvider("http://ethereum-rpc.publicnode.com");
    const makerWallet = maker.connect(provider);

    // Approve the makerAsset contract to spend on behalf of the maker
    const makerAssetContract = new Contract(makerAsset, erc20AbiFragment, makerWallet);
    const domain = getLimitOrderV4Domain(chainId);

    console.log('Approving makerAsset spend...', domain.verifyingContract, makerAsset);
    try {
        const approveTx = await makerAssetContract.approve(domain.verifyingContract, makingAmount);
        await approveTx.wait(); // Wait for the transaction to be mined
        console.log('Approval successful');
    } catch (error) {
        console.error('Error in approving makerAsset spend:', error);
        return { success: false, reason: "Failed to approve makerAsset spend." };
    }

    // see MakerTraits.ts
    const makerTraits = MakerTraits.default()
        .withExpiration(expiration)
        .allowPartialFills() // If you wish to allow partial fills
        .allowMultipleFills(); // And assuming multiple fills are also okay

    const order = new LimitOrder({
        makerAsset: new Address('0x55d398326f99059fF775485246999027B3197955'), //BUSD
        takerAsset: new Address('0x111111111117dc0aa78b770fa6a738034120c302'), //1INCH
        makingAmount: 1_000000n, // 1 USDT
        takingAmount: 1_00000000000000000n, // 10 1INCH
        maker: new Address(maker.address),
        salt: BigInt(Math.floor(Math.random() * 100000000)),
        receiver: new Address(maker.address),
    }, makerTraits)

    const typedData = order.getTypedData(domain)
    const signature = await maker.signTypedData(
        typedData.domain,
        { Order: typedData.types.Order },
        typedData.message
    )

    const api = new Api({
        networkId: chainId, // ethereum
        authKey: String(process.env.API_KEY), // get it at https://portal.1inch.dev/
        httpConnector: new AxiosProviderConnector()
    });

    // submit order 
    try {
        // @1inch/limit-order-sdk/dist/api/api.js, must edit the `submitOrder` method to return the promise
        let result = await api.submitOrder(order, signature);
        console.log('result', result);
    } catch (e) {
        console.log(e);
    }
    
    // must wait at least 1.05 seconds after submitting the order to query it
    await new Promise(resolve => setTimeout(resolve, 1050));

    // get order by hash
    const hash = order.getOrderHash(getLimitOrderV4Domain(chainId))
    const orderInfo = await api.getOrderByHash(hash);
    console.log('orderInfo', orderInfo);
})();
