using NBitcoin.DataEncoders;
using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace NBitcoin.Tests
{
	public class sidechains
	{

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public static void CreateWithdrawScript()
		{
			// build a sidechain genesis with a locked output of 1000 coins

			Transaction sidechainGenesis = new Transaction();
			sidechainGenesis.Version = 1;
			sidechainGenesis.Time = (uint) DateTime.UtcNow.ToUnixTimestamp();
			sidechainGenesis.AddInput(new TxIn
			{
				ScriptSig = new Script(Op.GetPushOp(Encoders.ASCII.DecodeData("Testing a sidechain")))
			});
			sidechainGenesis.AddOutput(new TxOut()
			{
				Value = Money.Coins(1000),
				ScriptPubKey = new Script(new Op
				{
					Code = OpcodeType.OP_WITHDRAWPROOFVERIFY,
					//PushData = new[] {(byte) 42}

				})
			});

			// build a withdraw lock transaction from parent chain that spends 500 coins

			var key = new Key();
			var network = Network.RegTest;

			// a block that has an output.
			var block = CreateBlockWithCoinbase(network, network.GetGenesis(), key, 1);
			var lockTrx = new Transaction();
			lockTrx.AddInput(new TxIn(new OutPoint(uint256.Zero, 0))); // a fake input that spends 250
			lockTrx.AddInput(new TxIn(new OutPoint(uint256.Zero, 0))); // a fake input that spends 250
			lockTrx.AddOutput(new TxOut(Money.Coins(500),
				new Script(new Op {Code = OpcodeType.OP_WITHDRAWPROOFVERIFY}))); // lock the output
			// TODO: how do we represent the target on the sidechain?
			block.AddTransaction(lockTrx);
			block.UpdateMerkleRoot();

			// mine two more blocks 
			var block1 = CreateBlockWithCoinbase(network, block, key, 2);
			var block2 = CreateBlockWithCoinbase(network, block1, key, 3);

			// Create an SPV proof, a transaction that can withdraw to the sidechain
			var proof = new SpvProof();
			proof.CoinBase = block.Transactions.First();
			proof.Lock = lockTrx;
			var merkleBlock = new MerkleBlock(block, new[] {lockTrx.GetHash()});
			proof.MerkleProof = merkleBlock.PartialMerkleTree;
			proof.SpvHeaders = new SpvHeaders {Headers = new List<BlockHeader> {block.Header, block1.Header, block2.Header}};
			proof.Genesis = network.GenesisHash;

			// verify the transaction script

			var scriptSignature = new Script(
				Op.GetPushOp(proof.Genesis.ToBytes()),
				Op.GetPushOp(proof.CoinBase.ToBytes()),
				Op.GetPushOp(proof.Lock.ToBytes()),
				Op.GetPushOp(proof.MerkleProof.ToBytes()),
				Op.GetPushOp(proof.SpvHeaders.ToBytes()));

			var withdrawTrx = new Transaction();
			withdrawTrx.AddInput(new TxIn(new OutPoint(sidechainGenesis, 0), scriptSignature));
			withdrawTrx.AddOutput(new TxOut(500, key.ScriptPubKey));
			withdrawTrx.AddOutput(new TxOut(500, new Script(new Op {Code = OpcodeType.OP_WITHDRAWPROOFVERIFY})));

			var scriptSig = withdrawTrx.Inputs.First().ScriptSig;
			var output = sidechainGenesis.Outputs.First();
			var scriptPubKey = sidechainGenesis.Outputs.First().ScriptPubKey;


			var result = Script.VerifyScript(scriptSig, scriptPubKey, withdrawTrx, 0);

		}


		private static Block CreateBlockWithCoinbase(Network network, Block previous, Key key, int index)
		{
			Block block = new Block();
			block.Header.HashPrevBlock = previous.GetHash(); 
			var tip = new ChainedBlock(previous.Header, index);
			block.Header.Bits = block.Header.GetWorkRequired(network, tip);
			block.Header.UpdateTime(network, tip);

			var coinbase = new Transaction();
			coinbase.AddInput(TxIn.CreateCoinbase(tip.Height + 1));
			coinbase.AddOutput(new TxOut(network.GetReward(tip.Height + 1), key));
			block.AddTransaction(coinbase);

			block.UpdateMerkleRoot();

			return block;
		}
	}
}
